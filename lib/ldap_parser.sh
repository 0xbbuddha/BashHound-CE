#!/usr/bin/env bash

################################################################################
# ldap_parser.sh - LDAP Response Parser
#
# This module parses hexadecimal LDAP responses into usable data.
#
# LDAP responses are ASN.1 BER-encoded binary data, represented as hex strings.
# This parser extracts specific attributes from SearchResultEntry responses:
#
# Common attributes:
# - distinguishedName: Object's full DN path
# - objectSid: Security Identifier (binary → S-1-5-21-...)
# - sAMAccountName: Short login name
# - member/memberOf: Group membership DNs
# - servicePrincipalName: Kerberos SPNs
# - userAccountControl: UAC flags (bitmask)
# - primaryGroupID: RID of primary group
# - Timestamps: whenCreated, lastLogon, pwdLastSet (Windows FileTime)
# - nTSecurityDescriptor: Security Descriptor (ACLs)
#
# Challenges:
# - ASN.1 supports multiple length encodings (short/long form)
# - Attribute values can be binary integers OR ASCII strings
# - Timestamps in GeneralizedTime format (YYYYMMDDHHmmss.0Z)
# - Must handle both expected and unexpected encodings
#
# All extraction functions return empty/default values on parse failure.
################################################################################

[[ -n "${_LDAP_PARSER_SH_LOADED:-}" ]] && return 0
readonly _LDAP_PARSER_SH_LOADED=1

parse_ldap_search_entry() {
    local hex_data="$1"

    if [[ ! "$hex_data" =~ 64 ]]; then
        return 1
    fi
    
    local entry_start=$(echo "$hex_data" | grep -b -o '64' | head -1 | cut -d: -f1)
    entry_start=$((entry_start / 2))
    
    local dn=""
    local attributes=()

    extract_attribute "$hex_data" "distinguishedName" "dn"
    extract_attribute "$hex_data" "sAMAccountName" "sam"
    extract_attribute "$hex_data" "objectSid" "sid"
    extract_attribute "$hex_data" "member" "members"
    extract_attribute "$hex_data" "memberOf" "memberof"
    extract_attribute "$hex_data" "name" "name"
    extract_attribute "$hex_data" "dNSHostName" "dns"
    extract_attribute "$hex_data" "operatingSystem" "os"
    extract_attribute "$hex_data" "userAccountControl" "uac"
    extract_attribute "$hex_data" "adminCount" "admincount"
    extract_attribute "$hex_data" "servicePrincipalName" "spn"
}

extract_attribute() {
    local hex_data="$1"
    local attr_name="$2"
    local output_var="$3"
    
    local attr_hex=$(printf '%s' "$attr_name" | xxd -p | tr -d '\n')

    if [[ "$hex_data" =~ 04[0-9a-f]{2}$attr_hex ]]; then
        return 0
    fi
    
    return 1
}

parse_ldap_response() {
    local hex_response="$1"
    local object_class="$2"

    local dn=$(extract_dn_from_response "$hex_response")
    local sam=$(extract_sam_from_response "$hex_response")
    local sid=$(extract_sid_from_response "$hex_response")
    
    cat <<EOF
{
  "dn": "$dn",
  "sAMAccountName": "$sam",
  "objectSid": "$sid",
  "objectClass": "$object_class"
}
EOF
}

extract_dn_from_response() {
    local hex="$1"
    
    if [[ "$hex" =~ 6484[0-9a-f]{8}04([0-9a-f]{2}) ]]; then
        local dn_len_hex="${BASH_REMATCH[1]}"
        local dn_len=$((16#$dn_len_hex))
        
        if [[ "$hex" =~ 6484[0-9a-f]{8}04[0-9a-f]{2}([0-9a-f]+) ]]; then
            local dn_hex="${BASH_REMATCH[1]:0:$((dn_len * 2))}"
            echo "$dn_hex" | xxd -r -p 2>/dev/null || echo ""
        fi
    elif [[ "$hex" =~ 6481[0-9a-f]{2}04([0-9a-f]{2}) ]]; then
        local dn_len_hex="${BASH_REMATCH[1]}"
        local dn_len=$((16#$dn_len_hex))
        
        if [[ "$hex" =~ 6481[0-9a-f]{2}04[0-9a-f]{2}([0-9a-f]+) ]]; then
            local dn_hex="${BASH_REMATCH[1]:0:$((dn_len * 2))}"
            echo "$dn_hex" | xxd -r -p 2>/dev/null || echo ""
        fi
    fi
}

extract_sam_from_response() {
    local hex="$1"
    
    local sam_attr_hex="73414d4163636f756e744e616d65"
    
    if [[ "$hex" =~ ${sam_attr_hex}3184[0-9a-f]{8}04([0-9a-f]{2})([0-9a-f]+) ]]; then
        local val_len_hex="${BASH_REMATCH[1]}"
        local val_len=$((16#$val_len_hex))
        local remaining="${BASH_REMATCH[2]}"
        local val_hex="${remaining:0:$((val_len * 2))}"
        echo "$val_hex" | xxd -r -p 2>/dev/null || echo ""
        return
    fi
    
    if [[ "$hex" =~ 040e${sam_attr_hex}31[0-9a-f]{2}04([0-9a-f]{2})([0-9a-f]+) ]]; then
        local val_len_hex="${BASH_REMATCH[1]}"
        local val_len=$((16#$val_len_hex))
        local remaining="${BASH_REMATCH[2]}"
        local val_hex="${remaining:0:$((val_len * 2))}"
        echo "$val_hex" | xxd -r -p 2>/dev/null || echo ""
        return
    fi
}

extract_sid_from_response() {
    local hex="$1"
    
    if [[ "$hex" =~ 73656375726974794964656e7469666965723184[0-9a-f]{8}04([0-9a-f]{2})([0-9a-f]+) ]]; then
        local sid_len_hex="${BASH_REMATCH[1]}"
        local sid_len=$((16#$sid_len_hex))
        local remaining="${BASH_REMATCH[2]}"
        local sid_hex="${remaining:0:$((sid_len * 2))}"
        
        if [ ${#sid_hex} -ge 16 ]; then
            convert_sid_hex_to_string "$sid_hex"
            return
        fi
    fi
    
    if [[ "$hex" =~ 73656375726974794964656e74696669657231[0-9a-f]{2}04([0-9a-f]{2})([0-9a-f]+) ]]; then
        local sid_len_hex="${BASH_REMATCH[1]}"
        local sid_len=$((16#$sid_len_hex))
        local remaining="${BASH_REMATCH[2]}"
        local sid_hex="${remaining:0:$((sid_len * 2))}"
        
        if [ ${#sid_hex} -ge 16 ]; then
            convert_sid_hex_to_string "$sid_hex"
            return
        fi
    fi
    
    if [[ "$hex" =~ 6f626a6563745369643184[0-9a-f]{8}04([0-9a-f]{2})([0-9a-f]+) ]]; then
        local sid_len_hex="${BASH_REMATCH[1]}"
        local sid_len=$((16#$sid_len_hex))
        local remaining="${BASH_REMATCH[2]}"
        local sid_hex="${remaining:0:$((sid_len * 2))}"
        
        if [ ${#sid_hex} -ge 16 ]; then
            convert_sid_hex_to_string "$sid_hex"
            return
        fi
    fi
    
    if [[ "$hex" =~ 6f626a65637453696431[0-9a-f]{2}04([0-9a-f]{2})([0-9a-f]+) ]]; then
        local sid_len_hex="${BASH_REMATCH[1]}"
        local sid_len=$((16#$sid_len_hex))
        local remaining="${BASH_REMATCH[2]}"
        local sid_hex="${remaining:0:$((sid_len * 2))}"
        
        if [ ${#sid_hex} -ge 16 ]; then
            convert_sid_hex_to_string "$sid_hex"
            return
        fi
    fi
    
    echo ""
}

convert_sid_hex_to_string() {
    local sid_hex="$1"
    
    if [ ${#sid_hex} -lt 16 ]; then
        echo ""
        return
    fi

    local revision=$((16#${sid_hex:0:2}))
    local sub_count=$((16#${sid_hex:2:2}))
    
    local authority_hex="${sid_hex:4:12}"
    local authority=$((16#$authority_hex))
    
    local sid="S-$revision-$authority"
    
    local offset=16
    for ((i=0; i<sub_count; i++)); do
        if [ $((offset + 8)) -gt ${#sid_hex} ]; then
            break
        fi
        local byte0="${sid_hex:$((offset)):2}"
        local byte1="${sid_hex:$((offset+2)):2}"
        local byte2="${sid_hex:$((offset+4)):2}"
        local byte3="${sid_hex:$((offset+6)):2}"
        local sub_hex="${byte3}${byte2}${byte1}${byte0}"
        local sub_val=$((16#$sub_hex))
        sid="$sid-$sub_val"
        offset=$((offset + 8))
    done
    
    echo "$sid"
}

extract_attribute_value() {
    local hex="$1"
    local attr_name="$2"
    
    local attr_hex=$(printf '%s' "$attr_name" | xxd -p | tr -d '\n')
    
    if [[ "$hex" =~ ${attr_hex}31([0-9a-f]{2})([0-9a-f]+) ]]; then
        local set_len_hex="${BASH_REMATCH[1]}"
        local set_len=$((16#$set_len_hex))
        local after_set="${BASH_REMATCH[2]}"
        
        if [ $set_len -ge 128 ]; then
            local num_bytes=$((set_len - 128))
            if [ $num_bytes -eq 1 ]; then
                set_len_hex="${after_set:0:2}"
                set_len=$((16#$set_len_hex))
                after_set="${after_set:2}"
            elif [ $num_bytes -eq 2 ]; then
                set_len_hex="${after_set:0:4}"
                set_len=$((16#$set_len_hex))
                after_set="${after_set:4}"
            elif [ $num_bytes -eq 3 ]; then
                set_len_hex="${after_set:0:6}"
                set_len=$((16#$set_len_hex))
                after_set="${after_set:6}"
            elif [ $num_bytes -eq 4 ]; then
                set_len_hex="${after_set:0:8}"
                set_len=$((16#$set_len_hex))
                after_set="${after_set:8}"
            fi
        fi
        
        if [[ "$after_set" =~ ^04([0-9a-f]{2})([0-9a-f]+) ]]; then
            local value_len_hex="${BASH_REMATCH[1]}"
            local value_len=$((16#$value_len_hex))
            local remaining="${BASH_REMATCH[2]}"
            
            if [ $value_len -ge 128 ]; then
                local num_bytes=$((value_len - 128))
                if [ $num_bytes -eq 1 ]; then
                    value_len_hex="${remaining:0:2}"
                    value_len=$((16#$value_len_hex))
                    remaining="${remaining:2}"
                elif [ $num_bytes -eq 2 ]; then
                    value_len_hex="${remaining:0:4}"
                    value_len=$((16#$value_len_hex))
                    remaining="${remaining:4}"
                fi
            fi
            
            if [ $value_len -gt 0 ] && [ $value_len -le 1000 ]; then
                local value_hex="${remaining:0:$((value_len * 2))}"
                echo "$value_hex" | xxd -r -p 2>/dev/null || echo ""
                return
            fi
        fi
    fi
    
    echo ""
}

extract_members_from_response() {
    local hex="$1"
    
    local member_hex="6d656d626572"
    
    if [[ ! "$hex" =~ $member_hex ]]; then
        echo ""
        return
    fi
    
    if [[ "$hex" =~ ${member_hex}31([0-9a-f]{2})([0-9a-f]+) ]]; then
        local set_len_hex="${BASH_REMATCH[1]}"
        local set_len=$((16#$set_len_hex))
        local after_member="${BASH_REMATCH[2]}"
        
        if [ $set_len -ge 128 ]; then
            local num_bytes=$((set_len - 128))
            if [ $num_bytes -eq 1 ]; then
                set_len_hex="${after_member:0:2}"
                set_len=$((16#$set_len_hex))
                after_member="${after_member:2}"
            elif [ $num_bytes -eq 2 ]; then
                set_len_hex="${after_member:0:4}"
                set_len=$((16#$set_len_hex))
                after_member="${after_member:4}"
            elif [ $num_bytes -eq 3 ]; then
                set_len_hex="${after_member:0:6}"
                set_len=$((16#$set_len_hex))
                after_member="${after_member:6}"
            elif [ $num_bytes -eq 4 ]; then
                set_len_hex="${after_member:0:8}"
                set_len=$((16#$set_len_hex))
                after_member="${after_member:8}"
            fi
        fi
        
        local data_to_parse="${after_member:0:$((set_len * 2))}"
        
        local members=()
        local remaining="$data_to_parse"
        
        while [[ "$remaining" =~ ^04([0-9a-f]{2})([0-9a-f]+) ]]; do
            local dn_len_hex="${BASH_REMATCH[1]}"
            local dn_len=$((16#$dn_len_hex))
            local rest="${BASH_REMATCH[2]}"
            
            if [ $dn_len -ge 128 ]; then
                local num_bytes=$((dn_len - 128))
                if [ $num_bytes -eq 1 ]; then
                    dn_len_hex="${rest:0:2}"
                    dn_len=$((16#$dn_len_hex))
                    rest="${rest:2}"
                elif [ $num_bytes -eq 2 ]; then
                    dn_len_hex="${rest:0:4}"
                    dn_len=$((16#$dn_len_hex))
                    rest="${rest:4}"
                fi
            fi
            
            if [ $dn_len -eq 0 ] || [ $dn_len -gt 1000 ]; then
                break
            fi
            
            local dn_hex="${rest:0:$((dn_len * 2))}"
            local dn=$(echo "$dn_hex" | xxd -r -p 2>/dev/null || echo "")
            
            if [[ "$dn" =~ (CN=|OU=|DC=) ]]; then
                members+=("$dn")
            fi
            
            remaining="${rest:$((dn_len * 2))}"
        done
        
        if [ ${#members[@]} -gt 0 ]; then
            printf '%s\n' "${members[@]}" | paste -sd '|'
        else
            echo ""
        fi
    else
        echo ""
    fi
}

extract_primary_group_id() {
    local hex="$1"
    
    local attr_hex="7072696d61727947726f75704944"
    
    # Format: attrName + 31 + (84 00 00 00 XX | XX) + 04 + YY + ASCII_value
    # Support both short and long form length encoding
    if [[ "$hex" =~ ${attr_hex}(31[0-9a-f]{2}|3184[0-9a-f]{8})04([0-9a-f]{2})([0-9a-f]+) ]]; then
        local str_len_hex="${BASH_REMATCH[2]}"
        local str_len=$((16#$str_len_hex))
        local remaining="${BASH_REMATCH[3]}"
        
        if [ $str_len -le 10 ]; then
            # Extract ASCII string and convert to integer
            local ascii_hex="${remaining:0:$((str_len * 2))}"
            local ascii_val=$(echo -n "$ascii_hex" | xxd -r -p 2>/dev/null)
            if [[ "$ascii_val" =~ ^[0-9]+$ ]]; then
                echo "$ascii_val"
                return
            fi
        fi
    fi
    
    echo ""
}

extract_filetime_timestamp() {
    local hex="$1"
    local attr_name="$2"
    
    local attr_hex=$(printf '%s' "$attr_name" | xxd -p | tr -d '\n')
    
    # Format: attrName + 31 + (84 00 00 00 XX | XX) + 04 + YY + GeneralizedTime
    # GeneralizedTime format: "20250729113919.0Z" (17 chars)
    if [[ "$hex" =~ ${attr_hex}(31[0-9a-f]{2}|3184[0-9a-f]{8})04([0-9a-f]{2})([0-9a-f]+) ]]; then
        local str_len_hex="${BASH_REMATCH[2]}"
        local str_len=$((16#$str_len_hex))
        local remaining="${BASH_REMATCH[3]}"
        
        if [ $str_len -ge 15 ] && [ $str_len -le 20 ]; then
            # Extract GeneralizedTime string (e.g., "20250729113919.0Z")
            local time_hex="${remaining:0:$((str_len * 2))}"
            local time_str=$(echo -n "$time_hex" | xxd -r -p 2>/dev/null)
            
            # Parse: YYYYMMDDHHmmss.?Z
            if [[ "$time_str" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2}) ]]; then
                local year="${BASH_REMATCH[1]}"
                local month="${BASH_REMATCH[2]}"
                local day="${BASH_REMATCH[3]}"
                local hour="${BASH_REMATCH[4]}"
                local minute="${BASH_REMATCH[5]}"
                local second="${BASH_REMATCH[6]}"
                
                # Convert to Unix timestamp using date command
                local unix_ts=$(date -d "${year}-${month}-${day} ${hour}:${minute}:${second} UTC" +%s 2>/dev/null)
                
                if [ -n "$unix_ts" ] && [ "$unix_ts" -gt 0 ]; then
                    echo "$unix_ts"
                    return
                fi
            fi
        fi
    fi
    
    echo "-1"
}

extract_uac_flags() {
    local hex="$1"
    
    local attr_hex="757365724163636f756e74436f6e74726f6c"
    
    # Format: attrName + 31 + (84 00 00 00 XX | XX) + 04 + YY + ASCII_value
    if [[ "$hex" =~ ${attr_hex}(31[0-9a-f]{2}|3184[0-9a-f]{8})04([0-9a-f]{2})([0-9a-f]+) ]]; then
        local str_len_hex="${BASH_REMATCH[2]}"
        local str_len=$((16#$str_len_hex))
        local remaining="${BASH_REMATCH[3]}"
        
        if [ $str_len -le 12 ]; then
            # Extract ASCII string and convert to integer
            local ascii_hex="${remaining:0:$((str_len * 2))}"
            local ascii_val=$(echo -n "$ascii_hex" | xxd -r -p 2>/dev/null)
            if [[ "$ascii_val" =~ ^[0-9]+$ ]]; then
                echo "$ascii_val"
                return
            fi
        fi
    fi
    
    echo "0"
}

extract_multi_valued_attribute() {
    local hex="$1"
    local attr_name="$2"
    
    local attr_hex=$(printf '%s' "$attr_name" | xxd -p | tr -d '\n')
    
    if [[ "$hex" =~ ${attr_hex}31([0-9a-f]{2})([0-9a-f]+) ]]; then
        local set_len_hex="${BASH_REMATCH[1]}"
        local set_len=$((16#$set_len_hex))
        local after_set="${BASH_REMATCH[2]}"
        
        if [ $set_len -ge 128 ]; then
            local num_bytes=$((set_len - 128))
            if [ $num_bytes -eq 1 ]; then
                set_len_hex="${after_set:0:2}"
                set_len=$((16#$set_len_hex))
                after_set="${after_set:2}"
            elif [ $num_bytes -eq 2 ]; then
                set_len_hex="${after_set:0:4}"
                set_len=$((16#$set_len_hex))
                after_set="${after_set:4}"
            elif [ $num_bytes -eq 3 ]; then
                set_len_hex="${after_set:0:6}"
                set_len=$((16#$set_len_hex))
                after_set="${after_set:6}"
            elif [ $num_bytes -eq 4 ]; then
                set_len_hex="${after_set:0:8}"
                set_len=$((16#$set_len_hex))
                after_set="${after_set:8}"
            fi
        fi
        
        local values=()
        local remaining="$after_set"
        local total_parsed=0
        
        while [ $total_parsed -lt $((set_len * 2)) ] && [[ "$remaining" =~ ^04([0-9a-f]{2})([0-9a-f]+) ]]; do
            local value_len_hex="${BASH_REMATCH[1]}"
            local value_len=$((16#$value_len_hex))
            remaining="${BASH_REMATCH[2]}"
            
            local header_len=2
            if [ $value_len -ge 128 ]; then
                local num_bytes=$((value_len - 128))
                header_len=$((2 + num_bytes * 2))
                if [ $num_bytes -eq 1 ]; then
                    value_len_hex="${remaining:0:2}"
                    value_len=$((16#$value_len_hex))
                    remaining="${remaining:2}"
                elif [ $num_bytes -eq 2 ]; then
                    value_len_hex="${remaining:0:4}"
                    value_len=$((16#$value_len_hex))
                    remaining="${remaining:4}"
                fi
            fi
            
            if [ $value_len -gt 0 ] && [ $value_len -le 1000 ]; then
                local value_hex="${remaining:0:$((value_len * 2))}"
                local value=$(echo "$value_hex" | xxd -r -p 2>/dev/null)
                if [ -n "$value" ]; then
                    values+=("$value")
                fi
                remaining="${remaining:$((value_len * 2))}"
                total_parsed=$((total_parsed + header_len + value_len * 2))
            else
                break
            fi
        done
        
        if [ ${#values[@]} -gt 0 ]; then
            local IFS='|'
            echo "${values[*]}"
        fi
    fi
}

parse_all_entries() {
    local hex_data="$1"
    local object_class="$2"
    
    local entries=()
    
    while [[ "$hex_data" =~ (3084[0-9a-f]{8}0201[0-9a-f]{2}64[0-9a-f]+)(3084|$) ]]; do
        local entry_hex="${BASH_REMATCH[1]}"
        
        local dn=$(extract_dn_from_response "$entry_hex")
        local sam=$(extract_sam_from_response "$entry_hex")
        local sid=$(extract_sid_from_response "$entry_hex")
        
        if [ -n "$dn" ]; then
            entries+=("{\"dn\":\"$dn\",\"sam\":\"$sam\",\"sid\":\"$sid\"}")
        fi
        
        hex_data="${hex_data#*$entry_hex}"
    done
    
    local IFS=','
    echo "[${entries[*]}]"
}

################################################################################
# AD CS PKI Bitmask Parsers
################################################################################

################################################################################
# extract_pki_cert_name_flag - Extract msPKI-Certificate-Name-Flag bitmask
#
# Args:
#   $1 - hex_response: Full LDAP response hex string
#
# Returns:
#   Integer value of the flag (default: 0)
#
# Flags (MS-CRTD 2.26):
#   0x00000001 = ENROLLEE_SUPPLIES_SUBJECT (ESC1 indicator)
#   0x00010000 = ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME
#   0x02000000 = SUBJECT_ALT_REQUIRE_UPN
################################################################################
extract_pki_cert_name_flag() {
    local hex_response="$1"
    
    local attr_hex="6d 73 50 4b 49 2d 43 65 72 74 69 66 69 63 61 74 65 2d 4e 61 6d 65 2d 46 6c 61 67"
    attr_hex=$(echo "$attr_hex" | tr -d ' ')
    
    if [[ "$hex_response" =~ $attr_hex ]]; then
        local after_attr="${hex_response#*$attr_hex}"
        
        if [[ "$after_attr" =~ 3184([0-9a-fA-F]{8})0202([0-9a-fA-F]{4}) ]]; then
            local value_hex="${BASH_REMATCH[2]}"
            echo $((16#$value_hex))
            return 0
        elif [[ "$after_attr" =~ 310402020001020[24]([0-9a-fA-F]{8}) ]]; then
            local value_hex="${BASH_REMATCH[1]}"
            local decimal=0
            for ((i=0; i<8; i+=2)); do
                local byte="${value_hex:$i:2}"
                decimal=$((decimal * 256 + 16#$byte))
            done
            echo "$decimal"
            return 0
        fi
    fi
    
    echo "0"
}

################################################################################
# extract_pki_enrollment_flag - Extract msPKI-Enrollment-Flag bitmask
#
# Args:
#   $1 - hex_response: Full LDAP response hex string
#
# Returns:
#   Integer value of the flag (default: 0)
#
# Flags (MS-CRTD 2.27):
#   0x00000002 = PEND_ALL_REQUESTS (requires manager approval)
#   0x00000020 = AUTO_ENROLLMENT
#   0x00000100 = USER_INTERACTION_REQUIRED
################################################################################
extract_pki_enrollment_flag() {
    local hex_response="$1"
    
    local attr_hex="6d 73 50 4b 49 2d 45 6e 72 6f 6c 6c 6d 65 6e 74 2d 46 6c 61 67"
    attr_hex=$(echo "$attr_hex" | tr -d ' ')
    
    if [[ "$hex_response" =~ $attr_hex ]]; then
        local after_attr="${hex_response#*$attr_hex}"
        
        if [[ "$after_attr" =~ 3184([0-9a-fA-F]{8})0202([0-9a-fA-F]{4}) ]]; then
            local value_hex="${BASH_REMATCH[2]}"
            echo $((16#$value_hex))
            return 0
        elif [[ "$after_attr" =~ 310402020001020[24]([0-9a-fA-F]{8}) ]]; then
            local value_hex="${BASH_REMATCH[1]}"
            local decimal=0
            for ((i=0; i<8; i+=2)); do
                local byte="${value_hex:$i:2}"
                decimal=$((decimal * 256 + 16#$byte))
            done
            echo "$decimal"
            return 0
        fi
    fi
    
    echo "0"
}

################################################################################
# extract_pki_private_key_flag - Extract msPKI-Private-Key-Flag bitmask
#
# Args:
#   $1 - hex_response: Full LDAP response hex string
#
# Returns:
#   Integer value of the flag (default: 0)
#
# Flags (MS-CRTD 2.28):
#   0x00000001 = REQUIRE_PRIVATE_KEY_ARCHIVAL
#   0x00000010 = EXPORTABLE_KEY (allows key export)
#   0x00000020 = STRONG_KEY_PROTECTION_REQUIRED
################################################################################
extract_pki_private_key_flag() {
    local hex_response="$1"
    
    local attr_hex="6d 73 50 4b 49 2d 50 72 69 76 61 74 65 2d 4b 65 79 2d 46 6c 61 67"
    attr_hex=$(echo "$attr_hex" | tr -d ' ')
    
    if [[ "$hex_response" =~ $attr_hex ]]; then
        local after_attr="${hex_response#*$attr_hex}"
        
        if [[ "$after_attr" =~ 3184([0-9a-fA-F]{8})0202([0-9a-fA-F]{4}) ]]; then
            local value_hex="${BASH_REMATCH[2]}"
            echo $((16#$value_hex))
            return 0
        elif [[ "$after_attr" =~ 310402020001020[24]([0-9a-fA-F]{8}) ]]; then
            local value_hex="${BASH_REMATCH[1]}"
            local decimal=0
            for ((i=0; i<8; i+=2)); do
                local byte="${value_hex:$i:2}"
                decimal=$((decimal * 256 + 16#$byte))
            done
            echo "$decimal"
            return 0
        fi
    fi
    
    echo "0"
}

################################################################################
# extract_multivalued_attribute - Extract multi-valued string attribute
#
# Args:
#   $1 - hex_response: Full LDAP response hex string
#   $2 - attribute_name: Name of attribute to extract
#
# Returns:
#   Comma-separated list of values
#
# Used for: certificateTemplates, pKIExtendedKeyUsage
################################################################################
extract_multivalued_attribute() {
    local hex_response="$1"
    local attr_name="$2"
    
    local attr_hex=$(echo -n "$attr_name" | xxd -p | tr -d '\n')
    
    if [[ "$hex_response" =~ $attr_hex ]]; then
        local after_attr="${hex_response#*$attr_hex}"
        local values=()
        
        while [[ "$after_attr" =~ 04([0-9a-fA-F]{2})([0-9a-fA-F]+) ]]; do
            local len_hex="${BASH_REMATCH[1]}"
            local len=$((16#$len_hex))
            local value_hex="${BASH_REMATCH[2]:0:$((len*2))}"
            
            local value=$(echo "$value_hex" | xxd -r -p 2>/dev/null)
            if [ -n "$value" ]; then
                values+=("$value")
            fi
            
            after_attr="${after_attr#*${BASH_REMATCH[0]}}"
            
            [[ ! "$after_attr" =~ ^04 ]] && break
        done
        
        if [ ${#values[@]} -gt 0 ]; then
            local IFS=','
            echo "${values[*]}"
            return 0
        fi
    fi
    
    echo ""
}

