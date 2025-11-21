#!/usr/bin/env bash

[[ -n "${_ASN1_SH_LOADED:-}" ]] && return 0
readonly _ASN1_SH_LOADED=1

readonly ASN1_BOOLEAN=0x01
readonly ASN1_INTEGER=0x02
readonly ASN1_OCTET_STRING=0x04
readonly ASN1_NULL=0x05
readonly ASN1_ENUMERATED=0x0a
readonly ASN1_SEQUENCE=0x30
readonly ASN1_SET=0x31

readonly LDAP_BIND_REQUEST=0x60
readonly LDAP_BIND_RESPONSE=0x61
readonly LDAP_UNBIND_REQUEST=0x42
readonly LDAP_SEARCH_REQUEST=0x63
readonly LDAP_SEARCH_RESULT_ENTRY=0x64
readonly LDAP_SEARCH_RESULT_DONE=0x65
readonly LDAP_MODIFY_REQUEST=0x66
readonly LDAP_MODIFY_RESPONSE=0x67

readonly LDAP_CONTEXT_0=0x80
readonly LDAP_CONTEXT_1=0x81
readonly LDAP_CONTEXT_2=0x82
readonly LDAP_CONTEXT_3=0x83
readonly LDAP_CONTEXT_7=0x87

asn1_encode_length() {
    local length=$1
    
    if [ "$length" -lt 128 ]; then
        printf '%02x' "$length"
    else
        local hex_length=$(printf '%x' "$length")
        local num_octets=$((${#hex_length} / 2))
        if [ $((${#hex_length} % 2)) -ne 0 ]; then
            hex_length="0$hex_length"
            ((num_octets++))
        fi
        printf '%02x%s' $((0x80 | num_octets)) "$hex_length"
    fi
}

asn1_encode_octet_string_hex() {
    local hex_value="$1"
    local length=$((${#hex_value} / 2))
    local length_encoded=$(asn1_encode_length "$length")
    printf '04%s%s' "$length_encoded" "$hex_value"
}

asn1_encode_oid() {
    local oid="$1"
    
    IFS='.' read -ra parts <<< "$oid"
    
    local first_byte=$(( 40 * ${parts[0]} + ${parts[1]} ))
    local hex_result=$(printf '%02x' "$first_byte")
    
    for ((i=2; i<${#parts[@]}; i++)); do
        local num=${parts[i]}
        local encoded=""
        
        if [ $num -lt 128 ]; then
            encoded=$(printf '%02x' "$num")
        else
            local bytes=()
            while [ $num -gt 0 ]; do
                bytes=($((num & 0x7f)) "${bytes[@]}")
                num=$((num >> 7))
            done
            
            for ((j=0; j<${#bytes[@]}; j++)); do
                local byte=${bytes[j]}
                if [ $j -lt $((${#bytes[@]} - 1)) ]; then
                    byte=$((byte | 0x80))
                fi
                encoded+=$(printf '%02x' "$byte")
            done
        fi
        
        hex_result+="$encoded"
    done
    
    local length=$((${#hex_result} / 2))
    printf '06'
    asn1_encode_length "$length"
    printf '%s' "$hex_result"
}

asn1_encode_integer() {
    local value=$1
    local hex_value=$(printf '%x' "$value")
    
    if [ $((${#hex_value} % 2)) -ne 0 ]; then
        hex_value="0$hex_value"
    fi
    
    local first_byte=$((0x${hex_value:0:2}))
    if [ "$first_byte" -ge 128 ]; then
        hex_value="00$hex_value"
    fi
    
    local length=$((${#hex_value} / 2))
    printf '%02x' "$ASN1_INTEGER"
    asn1_encode_length "$length"
    printf '%s' "$hex_value"
}

asn1_encode_octet_string() {
    local string="$1"
    local hex_string=$(printf '%s' "$string" | xxd -p | tr -d '\n')
    local length=$((${#hex_string} / 2))
    
    printf '%02x' "$ASN1_OCTET_STRING"
    asn1_encode_length "$length"
    printf '%s' "$hex_string"
}

asn1_encode_octet_string_with_tag() {
    local tag=$1
    local string="$2"
    local hex_string=$(printf '%s' "$string" | xxd -p | tr -d '\n')
    local length=$((${#hex_string} / 2))
    
    printf '%02x' "$tag"
    asn1_encode_length "$length"
    printf '%s' "$hex_string"
}

asn1_encode_sequence() {
    local content="$1"
    local length=$((${#content} / 2))
    
    printf '%02x' "$ASN1_SEQUENCE"
    asn1_encode_length "$length"
    printf '%s' "$content"
}

asn1_encode_sequence_with_tag() {
    local tag=$1
    local content="$2"
    local length=$((${#content} / 2))
    
    printf '%02x' "$tag"
    asn1_encode_length "$length"
    printf '%s' "$content"
}

asn1_encode_boolean() {
    local value=$1
    printf '%02x' "$ASN1_BOOLEAN"
    printf '01'
    if [ "$value" = "true" ] || [ "$value" = "1" ]; then
        printf 'ff'
    else
        printf '00'
    fi
}

asn1_encode_enumerated() {
    local value=$1
    printf '%02x' "$ASN1_ENUMERATED"
    printf '01'
    printf '%02x' "$value"
}

asn1_decode_length() {
    local hex_data="$1"
    local first_byte="0x${hex_data:0:2}"
    
    if [ "$first_byte" -lt 128 ]; then
        echo "$first_byte,2"
    else
        local num_octets=$((first_byte & 0x7f))
        local length_hex="${hex_data:2:$((num_octets * 2))}"
        local length=$((16#$length_hex))
        echo "$length,$((2 + num_octets * 2))"
    fi
}

asn1_decode_integer() {
    local hex_data="$1"
    local tag="0x${hex_data:0:2}"
    
    if [ "$tag" -ne "$ASN1_INTEGER" ]; then
        echo "ERROR: Not an INTEGER tag" >&2
        return 1
    fi
    
    local length_info=$(asn1_decode_length "${hex_data:2}")
    local length=$(echo "$length_info" | cut -d',' -f1)
    local consumed=$(echo "$length_info" | cut -d',' -f2)
    
    local value_hex="${hex_data:$((2 + consumed)):$((length * 2))}"
    local value=$((16#$value_hex))
    
    echo "$value"
}

asn1_decode_octet_string() {
    local hex_data="$1"
    local tag="0x${hex_data:0:2}"
    
    if [ "$tag" -ne "$ASN1_OCTET_STRING" ]; then
        echo "ERROR: Not an OCTET STRING tag" >&2
        return 1
    fi
    
    local length_info=$(asn1_decode_length "${hex_data:2}")
    local length=$(echo "$length_info" | cut -d',' -f1)
    local consumed=$(echo "$length_info" | cut -d',' -f2)
    
    local value_hex="${hex_data:$((2 + consumed)):$((length * 2))}"
    echo "$value_hex" | xxd -r -p
}

asn1_parse_tlv() {
    local hex_data="$1"
    
    if [ ${#hex_data} -lt 4 ]; then
        echo "ERROR: Data too short" >&2
        return 1
    fi
    
    local tag="0x${hex_data:0:2}"
    local length_info=$(asn1_decode_length "${hex_data:2}")
    local length=$(echo "$length_info" | cut -d',' -f1)
    local length_bytes=$(echo "$length_info" | cut -d',' -f2)
    
    local value_start=$((2 + length_bytes))
    local value_hex="${hex_data:$value_start:$((length * 2))}"
    local total_length=$((value_start + length * 2))
    
    echo "$tag,$length,$value_hex,$total_length"
}

hex_to_string() {
    local hex="$1"
    echo "$hex" | xxd -r -p 2>/dev/null || echo ""
}

string_to_hex() {
    local string="$1"
    printf '%s' "$string" | xxd -p | tr -d '\n'
}

