#!/usr/bin/env bash

# ldap.sh - Implémentation du protocole LDAP en bash pur
# RFC 4511 - Lightweight Directory Access Protocol (LDAP)

[[ -n "${_LDAP_SH_LOADED:-}" ]] && return 0
readonly _LDAP_SH_LOADED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$LIB_DIR/asn1.sh"

LDAP_HOST=""
LDAP_PORT=389
LDAP_FD=""
LDAP_MESSAGE_ID=1
LDAP_USE_TLS=false
LDAP_OPENSSL_PID=""
LDAP_AUTO_RECONNECT=true
LDAP_BIND_DN=""
LDAP_BIND_PASSWORD=""
LDAP_DEBUG="${LDAP_DEBUG:-false}"

ldap_connect() {
    local host="$1"
    local port="${2:-389}"
    local use_tls="${3:-auto}"
    
    LDAP_HOST="$host"
    LDAP_PORT="$port"
    
    if [ "$use_tls" = "auto" ]; then
        if [ "$port" = "636" ]; then
            use_tls="true"
        else
            use_tls="false"
        fi
    fi
    
    if [ "$use_tls" = "true" ]; then
        echo "INFO: Connexion LDAPS (TLS) à $host:$port..." >&2
        ldap_connect_tls "$host" "$port"
        return $?
    else
        [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Tentative de connexion LDAP (plain) à $host:$port..." >&2
        ldap_connect_plain "$host" "$port"
        return $?
    fi
}

ldap_connect_plain() {
    local host="$1"
    local port="$2"

    if ! ( exec 3<>"/dev/tcp/$host/$port" ) 2>/dev/null; then
        echo "ERROR: Impossible de se connecter à $host:$port" >&2
        echo "ERROR: Vérifiez que le serveur est accessible et écoute sur le port $port" >&2
        return 1
    fi
    
    exec 3<>"/dev/tcp/$host/$port"
    
    LDAP_FD=3
    LDAP_USE_TLS=false
    echo "INFO: Connexion LDAP établie à $host:$port" >&2
    return 0
}

ldap_connect_tls() {
    local host="$1"
    local port="$2"
    
    if ! command -v openssl &> /dev/null; then
        echo "ERROR: openssl n'est pas installé. LDAPS non disponible." >&2
        return 1
    fi
    
    if [ -n "$LDAP_OPENSSL_PID" ]; then
        kill "$LDAP_OPENSSL_PID" 2>/dev/null
        wait "$LDAP_OPENSSL_PID" 2>/dev/null
    fi
    rm -f "/tmp/bashhound_ldaps_in_$$" "/tmp/bashhound_ldaps_out_$$" 2>/dev/null
    
    local fifo_in="/tmp/bashhound_ldaps_in_$$"
    local fifo_out="/tmp/bashhound_ldaps_out_$$"
    
    mkfifo "$fifo_in" "$fifo_out" 2>/dev/null

    openssl s_client -quiet -connect "$host:$port" -ign_eof < "$fifo_in" > "$fifo_out" 2>/dev/null &
    LDAP_OPENSSL_PID=$!
    
    sleep 1
    
    if ! kill -0 "$LDAP_OPENSSL_PID" 2>/dev/null; then
        echo "ERROR: Échec de la connexion TLS" >&2
        rm -f "$fifo_in" "$fifo_out"
        LDAP_OPENSSL_PID=""
        return 1
    fi
    
    exec 3>"$fifo_in" 2>/dev/null
    exec 4<"$fifo_out" 2>/dev/null
    
    LDAP_FD=3
    LDAP_USE_TLS=true
    
    echo "INFO: Connexion LDAPS (TLS) établie à $host:$port (PID: $LDAP_OPENSSL_PID)" >&2
    return 0
}

ldap_reconnect() {
    echo "INFO: Reconnexion à $LDAP_HOST:$LDAP_PORT..." >&2

    local saved_dn="$LDAP_BIND_DN"
    local saved_password="$LDAP_BIND_PASSWORD"
    local was_tls="$LDAP_USE_TLS"
    
    ldap_disconnect
    
    local use_tls="false"
    if [ "$was_tls" = "true" ]; then
        use_tls="true"
        LDAP_USE_TLS=true
    fi
    
    ldap_connect "$LDAP_HOST" "$LDAP_PORT" "$use_tls"
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    if [ -n "$saved_dn" ]; then
        echo "INFO: Re-authentification après reconnexion..." >&2
        LDAP_BIND_DN="$saved_dn"
        LDAP_BIND_PASSWORD="$saved_password"
        ldap_bind "$saved_dn" "$saved_password"
        return $?
    fi
    
    return 0
}

ldap_disconnect() {
    if [ -n "$LDAP_FD" ]; then
        if [ "$LDAP_USE_TLS" = "true" ]; then
            exec 3>&- 2>/dev/null
            exec 4<&- 2>/dev/null
            
            if [ -n "$LDAP_OPENSSL_PID" ]; then
                kill "$LDAP_OPENSSL_PID" 2>/dev/null
                wait "$LDAP_OPENSSL_PID" 2>/dev/null
            fi
            
            rm -f "/tmp/bashhound_ldaps_in_$$" "/tmp/bashhound_ldaps_out_$$" 2>/dev/null
            
            echo "INFO: Connexion LDAPS fermée" >&2
        else
            exec 3>&-
            echo "INFO: Connexion LDAP fermée" >&2
        fi
        LDAP_FD=""
    fi
}

ldap_send_message() {
    local message_hex="$1"
    
    if [ -z "$LDAP_FD" ]; then
        echo "ERROR: Pas de connexion LDAP active" >&2
        return 1
    fi
    
    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Envoi de $((${#message_hex} / 2)) octets..." >&2
    
    if [ "$LDAP_USE_TLS" = "true" ] && [ -n "$LDAP_OPENSSL_PID" ]; then
        if ! kill -0 "$LDAP_OPENSSL_PID" 2>/dev/null; then
            echo "WARN: Connexion LDAPS perdue, reconnexion..." >&2
            if [ "$LDAP_AUTO_RECONNECT" = "true" ]; then
                ldap_reconnect
                if [ $? -ne 0 ]; then
                    echo "ERROR: Échec de reconnexion" >&2
                    return 1
                fi
            else
                return 1
            fi
        fi
    fi
    
    printf '%s' "$message_hex" | xxd -r -p >&3 2>/dev/null
    local ret=$?
    
    if [ $ret -eq 0 ]; then
        [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Message envoyé avec succès" >&2
    else
        echo "ERROR: Échec de l'envoi du message (ret=$ret)" >&2
        
        if [ "$LDAP_USE_TLS" = "true" ] && [ "$LDAP_AUTO_RECONNECT" = "true" ]; then
            echo "INFO: Tentative de reconnexion automatique..." >&2
            ldap_reconnect
            if [ $? -eq 0 ]; then
                echo "INFO: Reconnexion réussie, réessai d'envoi..." >&2
                printf '%s' "$message_hex" | xxd -r -p >&3 2>/dev/null
                ret=$?
            fi
        fi
    fi
    
    return $ret
}

ldap_receive_message() {
    if [ -z "$LDAP_FD" ]; then
        echo "ERROR: Pas de connexion LDAP active" >&2
        return 1
    fi
    
    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Début de la lecture de la réponse LDAP..." >&2
    
    local response=""
    local read_fd=3
    
    if [ "$LDAP_USE_TLS" = "true" ]; then
        read_fd=4
    fi
    
    local header=$(dd bs=1 count=2 <&$read_fd 2>/dev/null | xxd -p | tr -d '\n')
    
    if [ -z "$header" ] || [ ${#header} -lt 4 ]; then
        echo "ERROR: Pas de réponse du serveur" >&2
        return 1
    fi
    
    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Header reçu: $header" >&2
    response="$header"
    
    local length_byte=$((0x${header:2:2}))
    local total_length=0
    local length_bytes_read=2
    
    if [ "$length_byte" -lt 128 ]; then
        total_length=$length_byte
        [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Longueur forme courte: $total_length" >&2
    else
        local num_octets=$((length_byte & 0x7f))
        [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Longueur forme longue sur $num_octets octets" >&2
        local length_hex=$(dd bs=1 count=$num_octets <&$read_fd 2>/dev/null | xxd -p | tr -d '\n')
        
        if [ -z "$length_hex" ]; then
            echo "ERROR: Impossible de lire les octets de longueur" >&2
            return 1
        fi
        
        response+="$length_hex"
        
        length_hex=$(echo "$length_hex" | sed 's/^0*//')
        if [ -z "$length_hex" ]; then
            length_hex="0"
        fi
        
        total_length=$((16#$length_hex))
        length_bytes_read=$((2 + num_octets))
    fi
    
    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Longueur du contenu: $total_length octets" >&2
    
    if [ "$total_length" -gt 0 ]; then
        [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Lecture de $total_length octets de contenu..." >&2
        local content=$(dd bs=1 count=$total_length <&$read_fd 2>/dev/null | xxd -p | tr -d '\n')
        
        if [ ${#content} -lt $((total_length * 2)) ]; then
            echo "WARN: Contenu incomplet (attendu: $((total_length * 2)) hex chars, reçu: ${#content})" >&2
        fi
        
        response+="$content"
    fi
    
    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Réponse complète reçue (${#response} caractères hex)" >&2
    echo "$response"
}

ldap_create_message() {
    local message_id=$1
    local protocol_op="$2"
    local controls="${3:-}"  # Optionnel
    
    local message_id_encoded=$(asn1_encode_integer "$message_id")
    local message_content="${message_id_encoded}${protocol_op}${controls}"
    
    asn1_encode_sequence "$message_content"
}

ldap_bind() {
    local dn="$1"
    local password="$2"
    local version="${3:-3}"
    
    LDAP_BIND_DN="$dn"
    LDAP_BIND_PASSWORD="$password"
    
    echo "INFO: Tentative de bind avec DN: $dn" >&2
    
    local version_encoded=$(asn1_encode_integer "$version")
    
    local dn_encoded=$(asn1_encode_octet_string "$dn")
    
    local password_encoded=$(asn1_encode_octet_string_with_tag 0x80 "$password")
    
    local bind_request="${version_encoded}${dn_encoded}${password_encoded}"
    local bind_request_msg=$(asn1_encode_sequence_with_tag 0x60 "$bind_request")
    
    local ldap_message=$(ldap_create_message "$LDAP_MESSAGE_ID" "$bind_request_msg")
    ((LDAP_MESSAGE_ID++))
    
    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Message LDAP Bind généré: ${#ldap_message} caractères hex" >&2
    
    ldap_send_message "$ldap_message"
    if [ $? -ne 0 ]; then
        echo "ERROR: Échec de l'envoi de la requête Bind" >&2
        return 1
    fi
    
    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Attente de la réponse Bind..." >&2
    local response=$(ldap_receive_message)
    if [ $? -ne 0 ]; then
        echo "ERROR: Échec de réception de la réponse Bind" >&2
        return 1
    fi
    
    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Réponse Bind complète: $response" >&2
    
    if [[ "$response" =~ 61 ]]; then
        [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Tag BindResponse (0x61) trouvé" >&2
        
        if [[ "$response" =~ 0a0100 ]]; then
            echo "INFO: Bind réussi (resultCode=0)" >&2
            return 0
        elif [[ "$response" =~ 0a01([0-9a-f]{2}) ]]; then
            local error_code="0x${BASH_REMATCH[1]}"
            local error_code_dec=$((error_code))
            echo "ERROR: Bind échoué - resultCode=$error_code_dec" >&2
            
            case $error_code_dec in
                1) echo "ERROR: Operations error" >&2 ;;
                2) echo "ERROR: Protocol error" >&2 ;;
                7) echo "ERROR: Auth method not supported" >&2 ;;
                8) echo "ERROR: Strong auth required" >&2 ;;
                32) echo "ERROR: No such object" >&2 ;;
                34) echo "ERROR: Invalid DN syntax" >&2 ;;
                49) echo "ERROR: Invalid credentials" >&2 ;;
                *) echo "ERROR: Code d'erreur LDAP: $error_code_dec" >&2 ;;
            esac
            return 1
        else
            echo "ERROR: Impossible d'extraire le code de résultat" >&2
            return 1
        fi
    else
        echo "ERROR: Tag BindResponse (0x61) non trouvé dans la réponse" >&2
        return 1
    fi
}

ldap_search() {
    local base_dn="$1"
    local scope="${2:-2}"
    local filter="${3:-(&(objectClass=*))}"
    local attributes="${4:-*}"
    local use_sd_flags="${5:-false}"
    
    echo "INFO: Recherche LDAP - Base: $base_dn, Filter: $filter" >&2
    
    local base_encoded=$(asn1_encode_octet_string "$base_dn")
    
    local scope_encoded=$(asn1_encode_enumerated "$scope")
    
    local deref_encoded=$(asn1_encode_enumerated 0)
    
    local size_limit_encoded=$(asn1_encode_integer 0)
    
    local time_limit_encoded=$(asn1_encode_integer 0)
    
    local types_only_encoded=$(asn1_encode_boolean false)
    
    local filter_encoded=$(ldap_encode_filter "$filter")
    
    local attrs_encoded=$(ldap_encode_attributes "$attributes")
    
    local search_request="${base_encoded}${scope_encoded}${deref_encoded}${size_limit_encoded}${time_limit_encoded}${types_only_encoded}${filter_encoded}${attrs_encoded}"
    local search_request_msg=$(asn1_encode_sequence_with_tag 0x63 "$search_request")
    
    local controls=""
    if [ "$use_sd_flags" = "true" ] || [[ "$attributes" == *"nTSecurityDescriptor"* ]]; then
        
        local oid="1.2.840.113556.1.4.801"
        local oid_encoded=$(asn1_encode_octet_string "$oid")
        local flags_int=$(asn1_encode_integer 7)
        local value_seq=$(asn1_encode_sequence "$flags_int")
        local value_encoded=$(asn1_encode_octet_string_hex "$value_seq")
        local control=$(asn1_encode_sequence "${oid_encoded}${value_encoded}")
        controls=$(asn1_encode_sequence_with_tag 0xa0 "$control")
    fi
    
    local ldap_message=$(ldap_create_message "$LDAP_MESSAGE_ID" "$search_request_msg" "$controls")
    local current_msg_id=$LDAP_MESSAGE_ID
    ((LDAP_MESSAGE_ID++))
    
    if [ -n "$controls" ]; then
        echo "DEBUG: Sending LDAP message with controls" >&2
        echo "DEBUG: Message length: $((${#ldap_message} / 2)) bytes" >&2
        echo "DEBUG: First 200 chars: ${ldap_message:0:200}" >&2
    fi
    
    ldap_send_message "$ldap_message"
    
    local results=()
    local done=false
    
    while [ "$done" = false ]; do
        local response=$(ldap_receive_message)
        if [ $? -ne 0 ]; then
            echo "ERROR: Échec de réception de la réponse Search" >&2
            break
        fi
        
        if [[ "$response" =~ 64 ]]; then
            results+=("$response")
        elif [[ "$response" =~ 65 ]]; then
            done=true
            
            if [[ "$response" =~ 65.{2,}020100 ]]; then
                echo "INFO: Recherche terminée avec succès (${#results[@]} résultats)" >&2
            else
                echo "WARN: Recherche terminée avec erreur" >&2
            fi
        else
            echo "WARN: Type de réponse inconnu" >&2
            done=true
        fi
    done
    
    printf '%s\n' "${results[@]}"
}

ldap_encode_filter() {
    local filter="$1"
    
    if [[ "$filter" =~ ^\(([^=]+)=\*\)$ ]]; then
        local attr="${BASH_REMATCH[1]}"
        local attr_hex=$(string_to_hex "$attr")
        local length=$((${#attr_hex} / 2))
        printf '%02x' 0x87
        asn1_encode_length "$length"
        printf '%s' "$attr_hex"
    elif [[ "$filter" =~ ^\(([^=]+)=([^\)]+)\)$ ]]; then
        local attr="${BASH_REMATCH[1]}"
        local value="${BASH_REMATCH[2]}"
        
        local attr_encoded=$(asn1_encode_octet_string "$attr")
        local value_encoded=$(asn1_encode_octet_string "$value")
        local equality_content="${attr_encoded}${value_encoded}"
        
        asn1_encode_sequence_with_tag 0xa3 "$equality_content"
    elif [[ "$filter" =~ ^\(\&(.+)\)$ ]]; then
        local inner="${BASH_REMATCH[1]}"
        if [[ "$inner" == "(objectClass=*)" ]]; then
            local attr_hex=$(string_to_hex "objectClass")
            local length=$((${#attr_hex} / 2))
            local filter_content=""
            printf '%02x' 0x87
            asn1_encode_length "$length"
            printf '%s' "$attr_hex"
            filter_content="$filter_content$(printf '%02x' 0x87; asn1_encode_length "$length"; printf '%s' "$attr_hex")"
            
            printf '%02x' 0xa0
            asn1_encode_length "$((${#filter_content} / 2))"
            printf '%s' "$filter_content"
        fi
    else
        local attr_hex=$(string_to_hex "objectClass")
        local length=$((${#attr_hex} / 2))
        printf '%02x' 0x87
        asn1_encode_length "$length"
        printf '%s' "$attr_hex"
    fi
}

ldap_encode_attributes() {
    local attrs="$1"
    
    if [ "$attrs" = "*" ] || [ -z "$attrs" ]; then
        printf '%02x00' 0x30
    else
        local attrs_array=(${attrs//,/ })
        local encoded_attrs=""
        
        for attr in "${attrs_array[@]}"; do
            encoded_attrs+=$(asn1_encode_octet_string "$attr")
        done
        
        asn1_encode_sequence "$encoded_attrs"
    fi
}

ldap_unbind() {
    echo "INFO: Unbind LDAP" >&2
    
    local unbind_request="4200"
    
    local ldap_message=$(ldap_create_message "$LDAP_MESSAGE_ID" "$unbind_request")
    ((LDAP_MESSAGE_ID++))
    
    ldap_send_message "$ldap_message"
    
    ldap_disconnect
}

ldap_parse_search_entry() {
    local hex_data="$1"
    
    echo "$hex_data"
}

