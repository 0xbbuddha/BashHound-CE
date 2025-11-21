#!/usr/bin/env bash

[[ -n "${_ACL_PARSER_SH_LOADED:-}" ]] && return 0
readonly _ACL_PARSER_SH_LOADED=1

declare -gA ACE_TYPES=(
    [00]="ACCESS_ALLOWED"
    [01]="ACCESS_DENIED"
    [02]="SYSTEM_AUDIT"
    [03]="SYSTEM_ALARM"
    [05]="ACCESS_ALLOWED_OBJECT"
    [06]="ACCESS_DENIED_OBJECT"
    [07]="SYSTEM_AUDIT_OBJECT"
    [08]="SYSTEM_ALARM_OBJECT"
    [09]="ACCESS_ALLOWED_CALLBACK"
    [0a]="ACCESS_DENIED_CALLBACK"
    [0b]="ACCESS_ALLOWED_CALLBACK_OBJECT"
    [0c]="ACCESS_DENIED_CALLBACK_OBJECT"
    [0d]="SYSTEM_AUDIT_CALLBACK"
    [0e]="SYSTEM_ALARM_CALLBACK"
    [0f]="SYSTEM_AUDIT_CALLBACK_OBJECT"
    [10]="SYSTEM_ALARM_CALLBACK_OBJECT"
)

declare -gA ACE_FLAGS=(
    [01]="OBJECT_INHERIT_ACE"
    [02]="CONTAINER_INHERIT_ACE"
    [04]="NO_PROPAGATE_INHERIT_ACE"
    [08]="INHERIT_ONLY_ACE"
    [10]="INHERITED_ACE"
    [20]="SUCCESSFUL_ACCESS_ACE"
    [40]="FAILED_ACCESS_ACE"
)

declare -gA ACCESS_MASK_TO_RIGHT=(
    [10000000]="GenericAll"
    [20000000]="GenericWrite"
    [40000000]="GenericRead"
    [80000000]="GenericExecute"
    
    [00010000]="Delete"
    [00020000]="ReadControl"
    [00040000]="WriteDacl"
    [00080000]="WriteOwner"

    [00000001]="CreateChild"
    [00000002]="DeleteChild"
    [00000004]="ListChildren"
    [00000008]="Self"
    [00000010]="ReadProperty"
    [00000020]="WriteProperty"
    [00000040]="DeleteTree"
    [00000080]="ListObject"
    [00000100]="ExtendedRight"
)

declare -gA EXTENDED_RIGHTS=(
    ["00299570-246d-11d0-a768-00aa006e0529"]="ForceChangePassword"
    ["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"]="DCSync"
    ["1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"]="DCSync"
    ["89e95b76-444d-4c62-991a-0facbeda640c"]="DCSync"
    ["f3a64788-5306-11d1-a9c5-0000f80367c1"]="ValidatedSPN"
    ["3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"]="AddAllowedToAct"
    ["bf9679c0-0de6-11d0-a285-00aa003049e2"]="AddMember"
)

declare -gA PROPERTY_SETS=(
    ["4c164200-20c0-11d0-a768-00aa006e0529"]="WriteAccountRestrictions"
    ["bc0ac240-79a9-11d0-9020-00c04fc2d4cf"]="WriteMember"
)

parse_sid_from_hex() {
    local hex="$1"
    local len=${#hex}
    
    if [ $len -lt 16 ]; then
        return 1
    fi
    
    local revision="${hex:0:2}"
    local sub_auth_count_hex="${hex:2:2}"
    local sub_auth_count=$((16#$sub_auth_count_hex))
    
    local id_auth_hex="${hex:4:12}"
    local id_auth=$((16#$id_auth_hex))
    
    local sid="S-$((16#$revision))-$id_auth"
    
    local offset=16
    for ((i=0; i<sub_auth_count; i++)); do
        if [ $((offset + 8)) -gt $len ]; then
            break
        fi
        
        local sub_hex="${hex:$offset:8}"
        local sub_le="${sub_hex:6:2}${sub_hex:4:2}${sub_hex:2:2}${sub_hex:0:2}"
        local sub_val=$((16#$sub_le))
        
        sid="$sid-$sub_val"
        offset=$((offset + 8))
    done
    
    echo "$sid"
}

parse_security_descriptor() {
    local hex="$1"
    local len=${#hex}
    
    if [ $len -lt 40 ]; then
        return 1
    fi
    
    local offset_owner_hex="${hex:8:8}"
    local offset_group_hex="${hex:16:8}"
    local offset_sacl_hex="${hex:24:8}"
    local offset_dacl_hex="${hex:32:8}"
    
    local offset_dacl=$(( 16#${offset_dacl_hex:6:2}${offset_dacl_hex:4:2}${offset_dacl_hex:2:2}${offset_dacl_hex:0:2} ))
    
    if [ $offset_dacl -eq 0 ] || [ $((offset_dacl * 2)) -ge $len ]; then
        return 0
    fi
    
    parse_acl "${hex:$((offset_dacl * 2))}"
}

parse_acl() {
    local hex="$1"
    local len=${#hex}
    
    if [ $len -lt 16 ]; then
        return 1
    fi
    
    local revision="${hex:0:2}"
    local ace_count_hex="${hex:8:4}"
    local ace_count=$(( 16#${ace_count_hex:2:2}${ace_count_hex:0:2} ))
    
    if [ $ace_count -eq 0 ]; then
        return 0
    fi
    
    local offset=16
    
    for ((i=0; i<ace_count; i++)); do
        if [ $((offset + 8)) -gt $len ]; then
            break
        fi
        
        local ace_type_hex="${hex:$offset:2}"
        local ace_flags_hex="${hex:$((offset + 2)):2}"
        local ace_size_hex="${hex:$((offset + 4)):4}"
        
        local ace_size=$(( 16#${ace_size_hex:2:2}${ace_size_hex:0:2} ))
        
        if [ $ace_size -eq 0 ] || [ $((offset + ace_size * 2)) -gt $len ]; then
            break
        fi
        
        local ace_hex="${hex:$offset:$((ace_size * 2))}"
        
        parse_ace "$ace_hex" "$ace_type_hex" "$ace_flags_hex"
        
        offset=$((offset + ace_size * 2))
    done
}

parse_ace() {
    local ace_hex="$1"
    local type_hex="$2"
    local flags_hex="$3"
    
    local ace_len=${#ace_hex}
    
    if [[ ! "$type_hex" =~ ^(00|05|09|0b)$ ]]; then
        return 0
    fi
    
    local is_inherited="false"
    local flags_int=$((16#$flags_hex))
    if [ $((flags_int & 0x10)) -ne 0 ]; then
        is_inherited="true"
    fi
    
    local offset=8
    
    if [ $((offset + 8)) -gt $ace_len ]; then
        return 1
    fi
    
    local mask_hex="${ace_hex:$offset:8}"
    local mask_le="${mask_hex:6:2}${mask_hex:4:2}${mask_hex:2:2}${mask_hex:0:2}"
    local mask=$((16#$mask_le))
    offset=$((offset + 8))
    
    local object_type=""
    local inherited_object_type=""
    
    if [[ "$type_hex" =~ ^(05|0b)$ ]]; then
        if [ $((offset + 8)) -gt $ace_len ]; then
            return 1
        fi
        
        local obj_flags_hex="${ace_hex:$offset:8}"
        local obj_flags=$((16#${obj_flags_hex:6:2}${obj_flags_hex:4:2}${obj_flags_hex:2:2}${obj_flags_hex:0:2}))
        offset=$((offset + 8))
        
        if [ $((obj_flags & 0x01)) -ne 0 ]; then
            if [ $((offset + 32)) -gt $ace_len ]; then
                return 1
            fi
            object_type="${ace_hex:$offset:32}"
            offset=$((offset + 32))
        fi
        
        if [ $((obj_flags & 0x02)) -ne 0 ]; then
            if [ $((offset + 32)) -gt $ace_len ]; then
                return 1
            fi
            inherited_object_type="${ace_hex:$offset:32}"
            offset=$((offset + 32))
        fi
    fi
    
    local sid_hex="${ace_hex:$offset}"
    local principal_sid=$(parse_sid_from_hex "$sid_hex")
    
    if [ -z "$principal_sid" ]; then
        return 1
    fi
    
    local right_name=$(map_access_mask_to_right "$mask" "$object_type")
    
    if [ -n "$right_name" ]; then
        echo "$principal_sid|$right_name|$is_inherited"
    fi
}

map_access_mask_to_right() {
    local mask=$1
    local object_type_guid="$2"
    
    if [ -n "$object_type_guid" ]; then
        local g1="${object_type_guid:6:2}${object_type_guid:4:2}${object_type_guid:2:2}${object_type_guid:0:2}"
        local g2="${object_type_guid:10:2}${object_type_guid:8:2}"
        local g3="${object_type_guid:14:2}${object_type_guid:12:2}"
        local g4="${object_type_guid:16:4}"
        local g5="${object_type_guid:20:12}"
        object_type_guid="${g1}-${g2}-${g3}-${g4}-${g5}"
        object_type_guid=$(echo "$object_type_guid" | tr '[:upper:]' '[:lower:]')
    fi
    
    if [ $((mask & 0x10000000)) -ne 0 ]; then
        echo "GenericAll"
        return 0
    fi
    
    if [ $((mask & 0x00080000)) -ne 0 ]; then
        echo "WriteOwner"
        return 0
    fi
    
    if [ $((mask & 0x00040000)) -ne 0 ]; then
        echo "WriteDacl"
        return 0
    fi
    
    if [ $((mask & 0x20000000)) -ne 0 ]; then
        echo "GenericWrite"
        return 0
    fi
    
    if [ $((mask & 0x00000100)) -ne 0 ]; then
        if [ -n "$object_type_guid" ] && [ -n "${EXTENDED_RIGHTS[$object_type_guid]}" ]; then
            echo "${EXTENDED_RIGHTS[$object_type_guid]}"
            return 0
        fi
        if [ -z "$object_type_guid" ]; then
            echo "AllExtendedRights"
            return 0
        fi
    fi
    
    if [ $((mask & 0x00000020)) -ne 0 ]; then
        if [ -n "$object_type_guid" ]; then
            if [ "$object_type_guid" = "bf9679c0-0de6-11d0-a285-00aa003049e2" ]; then
                echo "AddMember"
                return 0
            fi
            if [ -n "${PROPERTY_SETS[$object_type_guid]}" ]; then
                echo "${PROPERTY_SETS[$object_type_guid]}"
                return 0
            fi
        fi
        echo "WriteProperty"
        return 0
    fi
    
    if [ $((mask & 0x00000008)) -ne 0 ]; then
        if [ -n "$object_type_guid" ]; then
            if [ "$object_type_guid" = "f3a64788-5306-11d1-a9c5-0000f80367c1" ]; then
                echo "WriteSPN"
                return 0
            fi
        fi
    fi
    
    if [ $((mask & 0x00000010)) -ne 0 ]; then
        if [ -n "$object_type_guid" ]; then
            if [ "$object_type_guid" = "ea1dddc4-60ff-416e-8cc0-17cee534bce8" ]; then
                echo "ReadLAPSPassword"
                return 0
            fi
            if [ "$object_type_guid" = "e362ed86-b728-0842-b27d-2dea7a9df218" ]; then
                echo "ReadGMSAPassword"
                return 0
            fi
        fi
    fi
    
    return 1
}

extract_aces_from_ldap_response() {
    local hex="$1"
    
    local ntsd_hex="6e54536563757269747944657363726970746f72"
    
    if [[ ! "$hex" =~ $ntsd_hex ]]; then
        return 0
    fi
    
    if [[ "$hex" =~ $ntsd_hex(.+) ]]; then
        local after="${BASH_REMATCH[1]}"
        local tag="${after:0:2}"
        
        if [ "$tag" = "31" ]; then
            local len_byte="${after:2:2}"
            local len=$((16#$len_byte))
            local offset=4
            
            if [ $len -gt 127 ]; then
                if [ "$len_byte" = "84" ]; then
                    local len_hex="${after:4:8}"
                    len=$((16#$len_hex))
                    offset=12
                elif [ "$len_byte" = "82" ]; then
                    local len_hex="${after:4:4}"
                    len=$((16#$len_hex))
                    offset=8
                elif [ "$len_byte" = "81" ]; then
                    len=$((16#${after:4:2}))
                    offset=6
                fi
            fi
            
            after="${after:offset}"
            tag="${after:0:2}"
            
            if [ "$tag" = "04" ]; then
                local len_byte="${after:2:2}"
                local len=$((16#$len_byte))
                local offset=4
                
                if [ $len -gt 127 ]; then
                    if [ "$len_byte" = "84" ]; then
                        local len_hex="${after:4:8}"
                        len=$((16#$len_hex))
                        offset=12
                    elif [ "$len_byte" = "82" ]; then
                        local len_hex="${after:4:4}"
                        len=$((16#$len_hex))
                        offset=8
                    elif [ "$len_byte" = "81" ]; then
                        len=$((16#${after:4:2}))
                        offset=6
                    fi
                fi
                
                if [ $len -gt 0 ] && [ $len -le 100000 ]; then
                    local sd_hex="${after:offset:$((len * 2))}"
                    parse_security_descriptor "$sd_hex"
                fi
            fi
        fi
    fi
}
