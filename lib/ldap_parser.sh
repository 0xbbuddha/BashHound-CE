#!/usr/bin/env bash

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
    
    if [[ "$hex" =~ ${attr_hex}31[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+) ]]; then
        local int_len_hex="${BASH_REMATCH[1]}"
        local int_len=$((16#$int_len_hex))
        local remaining="${BASH_REMATCH[2]}"
        
        if [ $int_len -le 4 ]; then
            local int_hex="${remaining:0:$((int_len * 2))}"
            local int_val=$((16#$int_hex))
            echo "$int_val"
            return
        fi
    fi
    
    echo ""
}

extract_filetime_timestamp() {
    local hex="$1"
    local attr_name="$2"
    
    local attr_hex=$(printf '%s' "$attr_name" | xxd -p | tr -d '\n')
    
    if [[ "$hex" =~ ${attr_hex}31[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+) ]]; then
        local int_len_hex="${BASH_REMATCH[1]}"
        local int_len=$((16#$int_len_hex))
        local remaining="${BASH_REMATCH[2]}"
        
        if [ $int_len -eq 8 ]; then
            local b0="${remaining:0:2}"
            local b1="${remaining:2:2}"
            local b2="${remaining:4:2}"
            local b3="${remaining:6:2}"
            local b4="${remaining:8:2}"
            local b5="${remaining:10:2}"
            local b6="${remaining:12:2}"
            local b7="${remaining:14:2}"
            
            local filetime_hex="${b7}${b6}${b5}${b4}${b3}${b2}${b1}${b0}"
            
            local filetime=$((16#$filetime_hex))
            
            if [ $filetime -eq 0 ]; then
                echo "-1"
            else
                local unix_ts=$(( (filetime / 10000000) - 11644473600 ))
                echo "$unix_ts"
            fi
            return
        fi
    fi
    
    echo "-1"
}

extract_uac_flags() {
    local hex="$1"
    
    local attr_hex="757365724163636f756en74436f6e74726f6c"
    
    if [[ "$hex" =~ ${attr_hex}31[0-9a-f]{2}02([0-9a-f]{2})([0-9a-f]+) ]]; then
        local int_len_hex="${BASH_REMATCH[1]}"
        local int_len=$((16#$int_len_hex))
        local remaining="${BASH_REMATCH[2]}"
        
        if [ $int_len -le 4 ]; then
            local int_hex="${remaining:0:$((int_len * 2))}"
            local uac=$((16#$int_hex))
            echo "$uac"
            return
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

