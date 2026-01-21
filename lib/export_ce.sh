#!/usr/bin/env bash

################################################################################
# export_ce.sh - BloodHound Community Edition v6 JSON Export
#
# This module transforms collected AD data into BloodHound CE compatible JSON.
#
# Main responsibilities:
# - Read pipe-delimited temporary files from collectors
# - Resolve relationships (group memberships, ACLs, parent/child)
# - Format data into BloodHound CE v6 JSON structure
# - Create separate JSON files per object type:
#   * bloodhound_users_*.json
#   * bloodhound_groups_*.json
#   * bloodhound_computers_*.json
#   * bloodhound_domains_*.json
#   * bloodhound_gpos_*.json
#   * bloodhound_ous_*.json
#   * bloodhound_containers_*.json
#   * bloodhound_certtemplates_*.json
#   * bloodhound_enterpriseca_*.json
#   * bloodhound_ntauthstores_*.json
#   * bloodhound_aiacas_*.json
#   * bloodhound_rootcas_*.json
#   * bloodhound_issuancepolicies_*.json
#
# Key features:
# - High-value group detection (well-known SIDs + adminCount)
# - GPLink parsing with IsEnforced flag
# - ACL/ACE transformation
# - ContainedBy resolution (parent OU/Container lookup)
#
# Reference: https://bloodhound.specterops.io/integrations/bloodhound-api/json-formats
################################################################################

[[ -n "${_EXPORT_SH_LOADED:-}" ]] && return 0
readonly _EXPORT_SH_LOADED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

resolve_principal_type() {
    local principal_sid="$1"
    
    local users_file="/tmp/bashhound_users_$$"
    local groups_file="/tmp/bashhound_groups_$$"
    local computers_file="/tmp/bashhound_computers_$$"
    
    if [ -f "$users_file" ] && grep -q "|$principal_sid|" "$users_file" 2>/dev/null; then
        echo "User"
        return 0
    fi
    
    if [ -f "$groups_file" ] && grep -q "|$principal_sid|" "$groups_file" 2>/dev/null; then
        echo "Group"
        return 0
    fi
    
    if [ -f "$computers_file" ] && grep -q "|$principal_sid|" "$computers_file" 2>/dev/null; then
        echo "Computer"
        return 0
    fi
    
    case "$principal_sid" in
        S-1-5-21-*-512|S-1-5-21-*-519|S-1-5-21-*-498) echo "Group" ;;
        S-1-5-21-*-500) echo "User" ;;
        S-1-5-21-*) echo "Group" ;;
        S-1-5-32-*) echo "Group" ;;
        S-1-5-9) echo "Group" ;;
        S-1-5-18|S-1-5-19|S-1-5-20) echo "User" ;;
        S-1-1-0) echo "Group" ;;
        S-1-5-11) echo "Group" ;;
        *) echo "Unknown" ;;
    esac
}

resolve_contained_by() {
    local dn_upper="$1"
    local domain_sid="$2"
    
    # Extraire le parent DN (tout après la première virgule)
    local parent_dn=$(echo "$dn_upper" | sed 's/^[^,]*,//')
    
    # Si le parent est le domaine racine (DC=...,DC=...), return null
    if [[ "$parent_dn" =~ ^DC= ]]; then
        echo "null"
        return 0
    fi
    
    # Chercher le parent dans les OUs
    # Use exported variable from collectors.sh if available, otherwise fallback to PID-based path
    local ous_file="${COLLECTED_OUS:-/tmp/bashhound_ous_$$}"
    if [ -f "$ous_file" ] && [ -s "$ous_file" ]; then
        while IFS='|' read -r ou_dn ou_name gplink blocks_inheritance description; do
            if [ -n "$ou_dn" ]; then
                local ou_dn_upper=$(echo "$ou_dn" | tr '[:lower:]' '[:upper:]')
                if [ "$ou_dn_upper" = "$parent_dn" ]; then
                    # Générer le GUID de l'OU (MD5 du DN)
                    local ou_guid=$(echo -n "$ou_dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                    echo "{\"ObjectIdentifier\":\"$ou_guid\",\"ObjectType\":\"OU\"}"
                    return 0
                fi
            fi
        done < "$ous_file"
    fi
    
    # Chercher le parent dans les Containers
    # Use exported variable from collectors.sh if available, otherwise fallback to PID-based path
    local containers_file="${COLLECTED_CONTAINERS:-/tmp/bashhound_containers_$$}"
    if [ -f "$containers_file" ] && [ -s "$containers_file" ]; then
        while IFS='|' read -r container_dn container_name description; do
            if [ -n "$container_dn" ]; then
                local container_dn_upper=$(echo "$container_dn" | tr '[:lower:]' '[:upper:]')
                if [ "$container_dn_upper" = "$parent_dn" ]; then
                    # Générer le GUID du Container
                    local container_guid=$(echo -n "$container_dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                    echo "{\"ObjectIdentifier\":\"$container_guid\",\"ObjectType\":\"Container\"}"
                    return 0
                fi
            fi
        done < "$containers_file"
    fi
    
    # Si pas trouvé, retourner null
    echo "null"
}

build_aces_json() {
    local object_id="$1"
    local aces_file="/tmp/bashhound_aces_$$"
    
    if [ ! -f "$aces_file" ]; then
        echo "[]"
        return 0
    fi
    
    local ace_objs=()
    
    while IFS='|' read -r obj_id obj_type principal_sid right_name is_inherited; do
        if [ "$obj_id" = "$object_id" ] && [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
            local principal_type=$(resolve_principal_type "$principal_sid")
            
            local ace_json=$(cat <<ACEJSON
{"PrincipalSID":"$principal_sid","PrincipalType":"$principal_type","RightName":"$right_name","IsInherited":$is_inherited,"InheritanceHash":""}
ACEJSON
)
            ace_objs+=("$ace_json")
        fi
    done < "$aces_file"
    
    if [ ${#ace_objs[@]} -gt 0 ]; then
        echo "[$(IFS=,; echo "${ace_objs[*]}")]"
    else
        echo "[]"
    fi
}

build_aces_json_certtemplate() {
    local object_id="$1"
    local aces_file="/tmp/bashhound_aces_$$"
    
    if [ ! -f "$aces_file" ]; then
        echo "[]"
        return 0
    fi
    
    local ace_objs=()
    
    while IFS='|' read -r obj_id obj_type principal_sid right_name is_inherited; do
        if [ "$obj_id" = "$object_id" ] && [ "$obj_type" = "CertTemplate" ] && [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
            local principal_type=$(resolve_principal_type "$principal_sid")
            
            local ace_json=$(cat <<ACEJSON
{"PrincipalSID":"$principal_sid","PrincipalType":"$principal_type","RightName":"$right_name","IsInherited":$is_inherited,"InheritanceHash":""}
ACEJSON
)
            ace_objs+=("$ace_json")
        fi
    done < "$aces_file"
    
    if [ ${#ace_objs[@]} -gt 0 ]; then
        echo "[$(IFS=,; echo "${ace_objs[*]}")]"
    else
        echo "[]"
    fi
}

build_aces_json_enterpriseca() {
    local object_id="$1"
    local aces_file="/tmp/bashhound_aces_$$"
    
    if [ ! -f "$aces_file" ]; then
        echo "[]"
        return 0
    fi
    
    local ace_objs=()
    
    while IFS='|' read -r obj_id obj_type principal_sid right_name is_inherited; do
        if [ "$obj_id" = "$object_id" ] && [ "$obj_type" = "EnterpriseCA" ] && [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
            local principal_type=$(resolve_principal_type "$principal_sid")
            
            local ace_json=$(cat <<ACEJSON
{"PrincipalSID":"$principal_sid","PrincipalType":"$principal_type","RightName":"$right_name","IsInherited":$is_inherited,"InheritanceHash":""}
ACEJSON
)
            ace_objs+=("$ace_json")
        fi
    done < "$aces_file"
    
    if [ ${#ace_objs[@]} -gt 0 ]; then
        echo "[$(IFS=,; echo "${ace_objs[*]}")]"
    else
        echo "[]"
    fi
}

build_child_objects() {
    local parent_dn_upper="$1"
    
    local child_objs=()
    local users_file="/tmp/bashhound_users_$$"
    local groups_file="/tmp/bashhound_groups_$$"
    local computers_file="/tmp/bashhound_computers_$$"
    
    if [ -f "$users_file" ]; then
        while IFS='|' read -r dn sam sid rest; do
            local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
            if [[ "$dn_upper" == *",$parent_dn_upper" ]]; then
                local relative_dn="${dn_upper%,$parent_dn_upper}"
                if [[ "$relative_dn" != *","* ]]; then
                    child_objs+=("{\"ObjectIdentifier\":\"$sid\",\"ObjectType\":\"User\"}")
                fi
            fi
        done < "$users_file"
    fi
    
    if [ -f "$groups_file" ]; then
        while IFS='|' read -r dn sam sid rest; do
            local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
            if [[ "$dn_upper" == *",$parent_dn_upper" ]]; then
                local relative_dn="${dn_upper%,$parent_dn_upper}"
                if [[ "$relative_dn" != *","* ]]; then
                    child_objs+=("{\"ObjectIdentifier\":\"$sid\",\"ObjectType\":\"Group\"}")
                fi
            fi
        done < "$groups_file"
    fi
    
    if [ -f "$computers_file" ]; then
        while IFS='|' read -r dn sam sid rest; do
            local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
            if [[ "$dn_upper" == *",$parent_dn_upper" ]]; then
                local relative_dn="${dn_upper%,$parent_dn_upper}"
                if [[ "$relative_dn" != *","* ]]; then
                    child_objs+=("{\"ObjectIdentifier\":\"$sid\",\"ObjectType\":\"Computer\"}")
                fi
            fi
        done < "$computers_file"
    fi
    
    if [ ${#child_objs[@]} -gt 0 ]; then
        echo "[$(IFS=,; echo "${child_objs[*]}")]"
    else
        echo "[]"
    fi
}

# Parse GPLink attribute from LDAP into BloodHound Links format
# Format: [LDAP://CN={GUID},CN=Policies,...;options][...]
# Options: 0=enabled, 1=disabled, 2=enabled+enforced, 3=disabled+enforced
parse_gplinks() {
    local gplink_raw="$1"
    
    if [ -z "$gplink_raw" ] || [ "$gplink_raw" = "null" ]; then
        echo "[]"
        return
    fi
    
    local links=()
    
    # Extract each [LDAP://...;X] block
    while [[ "$gplink_raw" =~ \[LDAP://[^\]]+\] ]]; do
        local block="${BASH_REMATCH[0]}"
        gplink_raw="${gplink_raw#*${block}}"
        
        # Extract GUID from CN={GUID}
        if [[ "$block" =~ CN=\{([0-9A-Fa-f-]+)\} ]]; then
            local guid="${BASH_REMATCH[1]}"
            guid=$(echo "$guid" | tr '[:lower:]' '[:upper:]')
            
            # Extract options (last number before ])
            local options="0"
            if [[ "$block" =~ \;([0-3])\] ]]; then
                options="${BASH_REMATCH[1]}"
            fi
            
            # Determine if enforced (bit 1 set: options 2 or 3)
            local is_enforced="false"
            if [ "$options" = "2" ] || [ "$options" = "3" ]; then
                is_enforced="true"
            fi
            
            links+=("{\"IsEnforced\":$is_enforced,\"GUID\":\"$guid\"}")
        fi
    done
    
    if [ ${#links[@]} -gt 0 ]; then
        echo "[$(IFS=,; echo "${links[*]}")]"
    else
        echo "[]"
    fi
}

################################################################################
# resolve_spn_targets - Resolve SPNs to computer SIDs
#
# Args:
#   $1: Pipe-separated list of SPNs (e.g., "ldap/dc.domain.local|http/web.domain.local:80")
#   $2: Associative array name containing hostname → SID mapping
#
# Returns:
#   JSON array of SPNTarget objects: [{"ComputerSID":"S-1-5-21-...","Port":389},...]
################################################################################
resolve_spn_targets() {
    local spns="$1"
    local -n hostname_to_sid_ref="$2"
    
    if [ -z "$spns" ]; then
        echo "[]"
        return 0
    fi
    
    local targets=()
    IFS='|' read -ra spn_array <<< "$spns"
    
    for spn in "${spn_array[@]}"; do
        if [ -z "$spn" ]; then
            continue
        fi
        
        # SPN format: service/hostname[:port]
        # Extract hostname and port
        local hostname=""
        local port=""
        
        if [[ "$spn" =~ ^[^/]+/([^:]+):([0-9]+)$ ]]; then
            # service/hostname:port
            hostname="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        elif [[ "$spn" =~ ^[^/]+/([^:]+)$ ]]; then
            # service/hostname
            hostname="${BASH_REMATCH[1]}"
            # Default ports based on service
            if [[ "$spn" =~ ^ldap/ ]]; then
                port="389"
            elif [[ "$spn" =~ ^ldaps/ ]]; then
                port="636"
            elif [[ "$spn" =~ ^http/ ]]; then
                port="80"
            elif [[ "$spn" =~ ^https/ ]]; then
                port="443"
            else
                port="0"
            fi
        fi
        
        # Normalize hostname to lowercase
        hostname=$(echo "$hostname" | tr '[:upper:]' '[:lower:]')
        
        # Remove domain suffix if present (we'll try both with and without)
        local short_hostname="${hostname%%.*}"
        
        # Try to resolve to computer SID
        local computer_sid=""
        
        # Try exact match first
        if [ -n "${hostname_to_sid_ref[$hostname]:-}" ]; then
            computer_sid="${hostname_to_sid_ref[$hostname]}"
        # Try short hostname
        elif [ -n "${hostname_to_sid_ref[$short_hostname]:-}" ]; then
            computer_sid="${hostname_to_sid_ref[$short_hostname]}"
        # Try uppercase version
        elif [ -n "${hostname_to_sid_ref[${hostname^^}]:-}" ]; then
            computer_sid="${hostname_to_sid_ref[${hostname^^}]}"
        fi
        
        # Add to targets if resolved
        if [ -n "$computer_sid" ] && [ -n "$port" ]; then
            targets+=("{\"ComputerSID\":\"$computer_sid\",\"Port\":$port}")
        fi
    done
    
    if [ ${#targets[@]} -gt 0 ]; then
        echo "[$(IFS=,; echo "${targets[*]}")]"
    else
        echo "[]"
    fi
}

# Crée plusieurs fichiers JSON séparés par type (format officiel BloodHound)
# Ref: https://bloodhound.specterops.io/integrations/bloodhound-api/json-formats
export_create_json_files() {
    local domain="$1"
    local output_prefix="$2"
    local version="${3:-dev}"
    
    local users_file="/tmp/bashhound_users_$$"
    local groups_file="/tmp/bashhound_groups_$$"
    local computers_file="/tmp/bashhound_computers_$$"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local files_created=()
    
    # Build hostname → SID mapping from computers for SPN resolution
    declare -A hostname_to_sid_map
    if [ -f "$computers_file" ] && [ -s "$computers_file" ]; then
        while IFS='|' read -r _ comp_sam comp_sid _ _ _ _ _ _ _ _ _ comp_dns _ _ _ _; do
            if [ -n "$comp_dns" ] && [ -n "$comp_sid" ]; then
                local dns_lower=$(echo "$comp_dns" | tr '[:upper:]' '[:lower:]')
                hostname_to_sid_map["$dns_lower"]="$comp_sid"
                # Also add short hostname (before first dot)
                local short_dns="${dns_lower%%.*}"
                hostname_to_sid_map["$short_dns"]="$comp_sid"
            fi
            # Also try sAMAccountName without $ suffix
            if [ -n "$comp_sam" ] && [ -n "$comp_sid" ]; then
                local sam_clean="${comp_sam%$}"
                local sam_lower=$(echo "$sam_clean" | tr '[:upper:]' '[:lower:]')
                hostname_to_sid_map["$sam_lower"]="$comp_sid"
            fi
        done < "$computers_file"
    fi
    
    if [ -f "$users_file" ] && [ -s "$users_file" ]; then
        local users_data=()
        local user_count=0
        
        while IFS='|' read -r dn sam sid primary_gid description when_created last_logon last_logon_ts pwd_last_set uac admin_count spns display_name email title home_directory logon_script supported_enc_types allowed_to_delegate sid_history is_deleted is_acl_protected; do
            if [ -n "$sam" ]; then
                local domain_sid=$(echo "$sid" | sed 's/-[0-9]*$//')
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local user_name_upper=$(echo "$sam@$domain_upper" | tr '[:lower:]' '[:upper:]')
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                
                local primary_group_sid="null"
                if [ -n "$primary_gid" ] && [ "$primary_gid" != "0" ] && [ "$primary_gid" != "-1" ]; then
                    primary_group_sid="\"${domain_sid}-${primary_gid}\""
                fi
                
                local spns_json="[]"
                local has_spn="false"
                if [ -n "$spns" ]; then
                    local spn_objs=()
                    IFS='|' read -ra spn_array <<< "$spns"
                    for spn in "${spn_array[@]}"; do
                        if [ -n "$spn" ]; then
                            local spn_escaped=$(printf '%s' "$spn" | jq -Rs .)
                            spn_objs+=("$spn_escaped")
                        fi
                    done
                    if [ ${#spn_objs[@]} -gt 0 ]; then
                        spns_json="[$(IFS=,; echo "${spn_objs[*]}")]"
                        has_spn="true"
                    fi
                fi
                
                local desc_json="null"
                if [ -n "$description" ]; then
                    description="${description//\\/\\\\}"
                    description="${description//\"/\\\"}"
                    desc_json="\"$description\""
                fi
                
                local uac_enabled="true"
                local uac_disabled="false"
                local uac_pwd_not_reqd="false"
                local uac_dont_req_preauth="false"
                local uac_pwd_never_expires="false"
                local uac_trusted_for_delegation="false"
                local uac_trusted_to_auth="false"
                
                if [ -n "$uac" ] && [ "$uac" != "0" ]; then
                    if (( uac & 2 )); then
                        uac_enabled="false"
                        uac_disabled="true"
                    fi
                    if (( uac & 32 )); then
                        uac_pwd_not_reqd="true"
                    fi
                    if (( uac & 4194304 )); then
                        uac_dont_req_preauth="true"
                    fi
                    if (( uac & 65536 )); then
                        uac_pwd_never_expires="true"
                    fi
                    if (( uac & 524288 )); then
                        uac_trusted_for_delegation="true"
                    fi
                    if (( uac & 16777216 )); then
                        uac_trusted_to_auth="true"
                    fi
                fi
                
                local admin_count_bool="false"
                if [ "$admin_count" = "1" ]; then
                    admin_count_bool="true"
                fi
                
                # Convert isDeleted to boolean
                local is_deleted_bool="false"
                if [ "$is_deleted" = "TRUE" ] || [ "$is_deleted" = "true" ] || [ "$is_deleted" = "1" ]; then
                    is_deleted_bool="true"
                fi
                
                [ -z "$when_created" ] && when_created="-1"
                [ -z "$last_logon" ] && last_logon="-1"
                [ -z "$last_logon_ts" ] && last_logon_ts="-1"
                [ -z "$pwd_last_set" ] && pwd_last_set="-1"
                
                # Build supported encryption types array
                local supported_enc_json="[]"
                if [ -n "$supported_enc_types" ] && [ "$supported_enc_types" != "0" ]; then
                    local enc_array=()
                    local enc_val=$((supported_enc_types))
                    # Windows encryption type flags
                    (( enc_val & 1 )) && enc_array+=("\"DES-CBC-CRC\"")
                    (( enc_val & 2 )) && enc_array+=("\"DES-CBC-MD5\"")
                    (( enc_val & 4 )) && enc_array+=("\"RC4-HMAC\"")
                    (( enc_val & 8 )) && enc_array+=("\"AES128-CTS-HMAC-SHA1-96\"")
                    (( enc_val & 16 )) && enc_array+=("\"AES256-CTS-HMAC-SHA1-96\"")
                    if [ ${#enc_array[@]} -gt 0 ]; then
                        supported_enc_json="[$(IFS=,; echo "${enc_array[*]}")]"
                    fi
                fi
                
                # Build allowed to delegate array
                local allowed_delegate_json="[]"
                if [ -n "$allowed_to_delegate" ]; then
                    local delegate_array=()
                    IFS='|' read -ra delegates <<< "$allowed_to_delegate"
                    for spn in "${delegates[@]}"; do
                        if [ -n "$spn" ]; then
                            local spn_escaped=$(printf '%s' "$spn" | jq -Rs .)
                            delegate_array+=("$spn_escaped")
                        fi
                    done
                    if [ ${#delegate_array[@]} -gt 0 ]; then
                        allowed_delegate_json="[$(IFS=,; echo "${delegate_array[*]}")]"
                    fi
                fi
                
                # Determine if user is high value
                local high_value="false"
                if [ "$admin_count_bool" = "true" ]; then
                    high_value="true"
                fi
                # Check for well-known high-value RIDs
                if [[ "$sid" =~ -500$ ]] || [[ "$sid" =~ -502$ ]]; then  # Administrator, krbtgt
                    high_value="true"
                fi
                
                # Build SID history array
                local sidhistory_json="[]"
                local has_sidhistory="false"
                if [ -n "$sid_history" ]; then
                    local sidhistory_array=()
                    IFS='|' read -ra sids <<< "$sid_history"
                    for history_sid in "${sids[@]}"; do
                        if [ -n "$history_sid" ]; then
                            sidhistory_array+=("\"$history_sid\"")
                        fi
                    done
                    if [ ${#sidhistory_array[@]} -gt 0 ]; then
                        sidhistory_json="[$(IFS=,; echo "${sidhistory_array[*]}")]"
                        has_sidhistory="true"
                    fi
                fi
                
                # Resolve SPNs to computer targets
                local spn_targets_json="[]"
                if [ -n "$spns" ]; then
                    spn_targets_json=$(resolve_spn_targets "$spns" hostname_to_sid_map)
                fi
                
                local aces_json=$(build_aces_json "$sid")
                local contained_by=$(resolve_contained_by "$dn_upper" "$domain_sid")
                
                users_data+=("$(cat <<USEREOF
{
  "ObjectIdentifier": "$sid",
  "IsDeleted": $is_deleted_bool,
  "IsACLProtected": $is_acl_protected,
  "Properties": {
    "domain": "$domain_upper",
    "name": "$user_name_upper",
    "domainsid": "$domain_sid",
    "isaclprotected": $is_acl_protected,
    "distinguishedname": "$dn_upper",
    "highvalue": $high_value,
    "description": $desc_json,
    "whencreated": $when_created,
    "sensitive": false,
    "dontreqpreauth": $uac_dont_req_preauth,
    "passwordnotreqd": $uac_pwd_not_reqd,
    "unconstraineddelegation": $uac_trusted_for_delegation,
    "pwdneverexpires": $uac_pwd_never_expires,
    "enabled": $uac_enabled,
    "trustedtoauth": $uac_trusted_to_auth,
    "lastlogon": $last_logon,
    "lastlogontimestamp": $last_logon_ts,
    "pwdlastset": $pwd_last_set,
    "serviceprincipalnames": $spns_json,
    "hasspn": $has_spn,
    "displayname": "${display_name:-}",
    "email": "${email:-}",
    "title": "${title:-}",
    "homedirectory": "${home_directory:-}",
    "logonscript": "${logon_script:-}",
    "useraccountcontrol": ${uac:-0},
    "samaccountname": "$sam",
    "userpassword": "",
    "unixpassword": "",
    "unicodepassword": "",
    "sfupassword": "",
    "admincount": $admin_count_bool,
    "supportedencryptiontypes": $supported_enc_json,
    "sidhistory": $sidhistory_json,
    "allowedtodelegate": $allowed_delegate_json
  },
  "PrimaryGroupSID": $primary_group_sid,
  "SPNTargets": $spn_targets_json,
  "UnconstrainedDelegation": $uac_trusted_for_delegation,
  "DomainSID": "$domain_sid",
  "Aces": $aces_json,
  "AllowedToDelegate": $allowed_delegate_json,
  "ContainedBy": $contained_by,
  "HasSIDHistory": $sidhistory_json
}
USEREOF
)")
                ((user_count++))
            fi
        done < "$users_file"
        
        if [ $user_count -gt 0 ]; then
            local users_json
            local IFS=','
            users_json="[${users_data[*]}]"
            
            local users_file_out="${output_prefix}_users_${timestamp}.json"
            cat > "$users_file_out" <<EOF
{
  "data": $users_json,
  "meta": {
    "methods": 0,
    "type": "users",
    "count": $user_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
            files_created+=("$users_file_out")
            echo "INFO: Créé $users_file_out ($user_count users)" >&2
        fi
    fi
    
    if [ -f "$groups_file" ] && [ -s "$groups_file" ]; then
        local groups_data=()
        local group_count=0
        
        while IFS='|' read -r dn sam sid rest; do
            if [ -n "$sam" ]; then
                local admin_count="${rest##*|}"
                local temp="${rest%|*}"
                local when_created="${temp##*|}"
                temp="${temp%|*}"
                local description="${temp##*|}"
                local members="${temp%|*}"
                
                local domain_sid=$(echo "$sid" | sed 's/-[0-9]*$//')
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local group_name_upper=$(echo "$sam@$domain_upper" | tr '[:lower:]' '[:upper:]')
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                
                local desc_json="null"
                if [ -n "$description" ]; then
                    desc_json=$(printf '%s' "$description" | jq -Rs .)
                fi
                
                local admin_count_bool="false"
                local high_value_bool="false"
                if [ "$admin_count" = "1" ]; then
                    admin_count_bool="true"
                    high_value_bool="true"
                fi
                
                # Detect well-known high-value groups by SID pattern (works for any domain)
                # Check for built-in groups (S-1-5-32-XXX or DOMAIN-S-1-5-32-XXX)
                if [[ "$sid" =~ S-1-5-32-([0-9]+)$ ]]; then
                    local builtin_rid="${BASH_REMATCH[1]}"
                    case "$builtin_rid" in
                        544) high_value_bool="true" ;;  # Administrators
                        548) high_value_bool="true" ;;  # Account Operators
                        549) high_value_bool="true" ;;  # Server Operators
                        550) high_value_bool="true" ;;  # Print Operators
                        551) high_value_bool="true" ;;  # Backup Operators
                    esac
                # Check for domain groups (S-1-5-21-DOMAIN_SID-RID)
                elif [[ "$sid" =~ ^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-([0-9]+)$ ]]; then
                    local domain_rid="${BASH_REMATCH[1]}"
                    case "$domain_rid" in
                        512) high_value_bool="true" ;;  # Domain Admins
                        516) high_value_bool="true" ;;  # Domain Controllers
                        519) high_value_bool="true" ;;  # Enterprise Admins
                        520) high_value_bool="true" ;;  # Group Policy Creator Owners
                    esac
                fi
                
                [ -z "$when_created" ] && when_created="-1"
                
                local members_json="[]"
                if [ -n "$members" ]; then
                    local member_objs=()
                    IFS='|' read -ra member_dns <<< "$members"
                    for member_dn in "${member_dns[@]}"; do
                        if [ -n "$member_dn" ]; then
                            local resolved=$(resolve_dn_to_sid_and_type "$member_dn")
                            if [ -n "$resolved" ]; then
                                local member_sid="${resolved%|*}"
                                local member_type="${resolved#*|}"
                                member_objs+=("{\"ObjectIdentifier\":\"$member_sid\",\"ObjectType\":\"$member_type\"}")
                            fi
                        fi
                    done
                    
                    if [ ${#member_objs[@]} -gt 0 ]; then
                        members_json="[$(IFS=,; echo "${member_objs[*]}")]"
                    fi
                fi
                
                local aces_json=$(build_aces_json "$sid")
                local contained_by=$(resolve_contained_by "$dn_upper" "$domain_sid")
                
                groups_data+=("$(cat <<GROUPEOF
{
  "ObjectIdentifier": "$sid",
  "IsDeleted": false,
  "IsACLProtected": false,
  "ContainedBy": $contained_by,
  "Properties": {
    "domain": "$domain_upper",
    "domainsid": "$domain_sid",
    "highvalue": $high_value_bool,
    "name": "$group_name_upper",
    "distinguishedname": "$dn_upper",
    "admincount": $admin_count_bool,
    "description": $desc_json,
    "whencreated": $when_created,
    "samaccountname": "$sam",
    "isaclprotected": false
  },
  "Members": $members_json,
  "Aces": $aces_json
}
GROUPEOF
)")
                ((group_count++))
            fi
        done < "$groups_file"
        
        # Add well-known SID synthetic groups for ACL resolution
        # These groups don't exist as LDAP objects but appear frequently in ACLs
        local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
        local domain_sid_value=$(grep -m1 "|" "$groups_file" 2>/dev/null | cut -d'|' -f3 | sed 's/-[0-9]*$//')
        
        if [ -n "$domain_sid_value" ]; then
            # S-1-1-0: EVERYONE
            groups_data+=("$(cat <<WKGEOF
{
  "ObjectIdentifier": "${domain_upper}-S-1-1-0",
  "IsDeleted": false,
  "IsACLProtected": false,
  "ContainedBy": null,
  "Properties": {
    "domain": "$domain_upper",
    "domainsid": "$domain_sid_value",
    "highvalue": false,
    "name": "EVERYONE@${domain_upper}",
    "distinguishedname": "",
    "admincount": false,
    "description": null,
    "whencreated": -1,
    "samaccountname": "Everyone",
    "isaclprotected": false
  },
  "Members": [],
  "Aces": []
}
WKGEOF
)")
            ((group_count++))
            
            # S-1-5-4: INTERACTIVE
            groups_data+=("$(cat <<WKGEOF
{
  "ObjectIdentifier": "${domain_upper}-S-1-5-4",
  "IsDeleted": false,
  "IsACLProtected": false,
  "ContainedBy": null,
  "Properties": {
    "domain": "$domain_upper",
    "domainsid": "$domain_sid_value",
    "highvalue": false,
    "name": "INTERACTIVE@${domain_upper}",
    "distinguishedname": "",
    "admincount": false,
    "description": null,
    "whencreated": -1,
    "samaccountname": "INTERACTIVE",
    "isaclprotected": false
  },
  "Members": [],
  "Aces": []
}
WKGEOF
)")
            ((group_count++))
            
            # S-1-5-9: ENTERPRISE DOMAIN CONTROLLERS
            groups_data+=("$(cat <<WKGEOF
{
  "ObjectIdentifier": "${domain_upper}-S-1-5-9",
  "IsDeleted": false,
  "IsACLProtected": false,
  "ContainedBy": null,
  "Properties": {
    "domain": "$domain_upper",
    "domainsid": "$domain_sid_value",
    "highvalue": true,
    "name": "ENTERPRISE DOMAIN CONTROLLERS@${domain_upper}",
    "distinguishedname": "",
    "admincount": false,
    "description": null,
    "whencreated": -1,
    "samaccountname": "ENTERPRISE DOMAIN CONTROLLERS",
    "isaclprotected": false
  },
  "Members": [],
  "Aces": []
}
WKGEOF
)")
            ((group_count++))
            
            # S-1-5-11: AUTHENTICATED USERS
            groups_data+=("$(cat <<WKGEOF
{
  "ObjectIdentifier": "${domain_upper}-S-1-5-11",
  "IsDeleted": false,
  "IsACLProtected": false,
  "ContainedBy": null,
  "Properties": {
    "domain": "$domain_upper",
    "domainsid": "$domain_sid_value",
    "highvalue": false,
    "name": "AUTHENTICATED USERS@${domain_upper}",
    "distinguishedname": "",
    "admincount": false,
    "description": null,
    "whencreated": -1,
    "samaccountname": "Authenticated Users",
    "isaclprotected": false
  },
  "Members": [],
  "Aces": []
}
WKGEOF
)")
            ((group_count++))
            
            # S-1-5-15: THIS ORGANIZATION
            groups_data+=("$(cat <<WKGEOF
{
  "ObjectIdentifier": "${domain_upper}-S-1-5-15",
  "IsDeleted": false,
  "IsACLProtected": false,
  "ContainedBy": null,
  "Properties": {
    "domain": "$domain_upper",
    "domainsid": "$domain_sid_value",
    "highvalue": false,
    "name": "THIS ORGANIZATION@${domain_upper}",
    "distinguishedname": "",
    "admincount": false,
    "description": null,
    "whencreated": -1,
    "samaccountname": "This Organization",
    "isaclprotected": false
  },
  "Members": [],
  "Aces": []
}
WKGEOF
)")
            ((group_count++))
            
            # Add synthetic duplicates for certain BUILTIN groups (without DN)
            # RustHound creates these for ACL resolution when the SID appears without full LDAP object
            # We only add the most commonly referenced BUILTIN groups in ACLs
            local builtin_groups=(
                "S-1-5-32-544|ADMINISTRATORS|Administrators"
                "S-1-5-32-548|ACCOUNT OPERATORS|Account Operators"
                "S-1-5-32-550|PRINT OPERATORS|Print Operators"
                "S-1-5-32-554|PRE-WINDOWS 2000 COMPATIBLE ACCESS|Pre-Windows 2000 Compatible Access"
                "S-1-5-32-557|INCOMING FOREST TRUST BUILDERS|Incoming Forest Trust Builders"
                "S-1-5-32-560|WINDOWS AUTHORIZATION ACCESS GROUP|Windows Authorization Access Group"
                "S-1-5-32-561|TERMINAL SERVER LICENSE SERVERS|Terminal Server License Servers"
            )
            
            for builtin in "${builtin_groups[@]}"; do
                IFS='|' read -r builtin_sid builtin_name builtin_sam <<< "$builtin"
                local is_highvalue="false"
                [[ "$builtin_sid" == "S-1-5-32-544" ]] && is_highvalue="true"  # Administrators
                [[ "$builtin_sid" == "S-1-5-32-548" ]] && is_highvalue="true"  # Account Operators
                
                groups_data+=("$(cat <<WKGEOF
{
  "ObjectIdentifier": "${domain_upper}-${builtin_sid}",
  "IsDeleted": false,
  "IsACLProtected": false,
  "ContainedBy": null,
  "Properties": {
    "domain": "$domain_upper",
    "domainsid": "$domain_sid_value",
    "highvalue": $is_highvalue,
    "name": "${builtin_name}@${domain_upper}",
    "distinguishedname": "",
    "admincount": false,
    "description": null,
    "whencreated": -1,
    "samaccountname": "$builtin_sam",
    "isaclprotected": false
  },
  "Members": [],
  "Aces": []
}
WKGEOF
)")
                ((group_count++))
            done
        fi
        
        if [ $group_count -gt 0 ]; then
            local groups_json
            local IFS=','
            groups_json="[${groups_data[*]}]"
            
            local groups_file_out="${output_prefix}_groups_${timestamp}.json"
            cat > "$groups_file_out" <<EOF
{
  "data": $groups_json,
  "meta": {
    "methods": 0,
    "type": "groups",
    "count": $group_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
            files_created+=("$groups_file_out")
            echo "INFO: Créé $groups_file_out ($group_count groups)" >&2
        fi
    fi
    
    if [ -f "$computers_file" ] && [ -s "$computers_file" ]; then
        local computers_data=()
        local computer_count=0
        
        while IFS='|' read -r dn sam sid primary_gid description operating_system when_created last_logon last_logon_ts pwd_last_set uac spns; do
            if [ -n "$sam" ]; then
                local comp_name="${sam%\$}"
                local domain_sid=$(echo "$sid" | sed 's/-[0-9]*$//')
                local comp_name_upper=$(echo "$comp_name" | tr '[:lower:]' '[:upper:]')
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                
                local primary_group_sid="null"
                if [ -n "$primary_gid" ] && [ "$primary_gid" != "0" ] && [ "$primary_gid" != "-1" ]; then
                    primary_group_sid="\"${domain_sid}-${primary_gid}\""
                fi
                
                local desc_json="null"
                if [ -n "$description" ]; then
                    desc_json=$(printf '%s' "$description" | jq -Rs .)
                fi
                
                local os_json="null"
                if [ -n "$operating_system" ]; then
                    os_json=$(printf '%s' "$operating_system" | jq -Rs .)
                fi
                
                local uac_enabled="true"
                local uac_trusted_for_delegation="false"
                local uac_trusted_to_auth="false"
                local uac_pwd_not_reqd="false"
                local uac_pwd_never_expires="false"
                
                if [ -n "$uac" ] && [ "$uac" != "0" ]; then
                    if (( uac & 2 )); then
                        uac_enabled="false"
                    fi
                    if (( uac & 32 )); then
                        uac_pwd_not_reqd="true"
                    fi
                    if (( uac & 65536 )); then
                        uac_pwd_never_expires="true"
                    fi
                    if (( uac & 524288 )); then
                        uac_trusted_for_delegation="true"
                    fi
                    if (( uac & 16777216 )); then
                        uac_trusted_to_auth="true"
                    fi
                fi
                
                local is_dc="false"
                local dc_registry_data="null"
                if [[ "$dn_upper" == *"OU=DOMAIN CONTROLLERS"* ]]; then
                    is_dc="true"
                    dc_registry_data='{"CertificateMappingMethods":null,"StrongCertificateBindingEnforcement":null}'
                fi
                
                [ -z "$when_created" ] && when_created="-1"
                [ -z "$last_logon" ] && last_logon="-1"
                [ -z "$last_logon_ts" ] && last_logon_ts="-1"
                [ -z "$pwd_last_set" ] && pwd_last_set="-1"
                
                local spns_json="[]"
                if [ -n "$spns" ]; then
                    local spn_objs=()
                    IFS='|' read -ra spn_array <<< "$spns"
                    for spn in "${spn_array[@]}"; do
                        if [ -n "$spn" ]; then
                            local spn_escaped=$(printf '%s' "$spn" | jq -Rs .)
                            spn_objs+=("$spn_escaped")
                        fi
                    done
                    if [ ${#spn_objs[@]} -gt 0 ]; then
                        spns_json="[$(IFS=,; echo "${spn_objs[*]}")]"
                    fi
                fi
                
                local aces_json=$(build_aces_json "$sid")
                
                computers_data+=("$(cat <<COMPEOF
{
  "ObjectIdentifier": "$sid",
  "IsDeleted": false,
  "IsACLProtected": false,
  "Properties": {
    "description": $desc_json,
    "distinguishedname": "$dn_upper",
    "domain": "$domain_upper",
    "domainsid": "$domain_sid",
    "enabled": $uac_enabled,
    "haslaps": false,
    "highvalue": false,
    "isaclprotected": false,
    "lastlogon": $last_logon,
    "lastlogontimestamp": $last_logon_ts,
    "name": "${comp_name_upper}.${domain_upper}",
    "operatingsystem": $os_json,
    "passwordnotreqd": $uac_pwd_not_reqd,
    "pwdlastset": $pwd_last_set,
    "pwdneverexpires": $uac_pwd_never_expires,
    "samaccountname": "$sam",
    "serviceprincipalnames": $spns_json,
    "sidhistory": [],
    "supportedencryptiontypes": [],
    "trustedtoauth": $uac_trusted_to_auth,
    "unconstraineddelegation": $uac_trusted_for_delegation,
    "whencreated": $when_created
  },
  "PrimaryGroupSID": $primary_group_sid,
  "LocalGroups": [],
  "Sessions": {
    "Results": [],
    "Collected": true,
    "FailureReason": null
  },
  "Status": null,
  "UnconstrainedDelegation": $uac_trusted_for_delegation,
  "DomainSID": "$domain_sid",
  "Aces": $aces_json,
  "AllowedToAct": [],
  "AllowedToDelegate": [],
  "ContainedBy": $contained_by,
  "DCRegistryData": $dc_registry_data,
  "DumpSMSAPassword": [],
  "HasSIDHistory": [],
  "IsDC": $is_dc,
  "PrivilegedSessions": {
    "Results": [],
    "Collected": false,
    "FailureReason": null
  },
  "RegistrySessions": {
    "Results": [],
    "Collected": false,
    "FailureReason": null
  },
  "UserRights": []
}
COMPEOF
)")
                ((computer_count++))
            fi
        done < "$computers_file"
        
        if [ $computer_count -gt 0 ]; then
            local computers_json
            local IFS=','
            computers_json="[${computers_data[*]}]"
            
            local computers_file_out="${output_prefix}_computers_${timestamp}.json"
            cat > "$computers_file_out" <<EOF
{
  "data": $computers_json,
  "meta": {
    "methods": 0,
    "type": "computers",
    "count": $computer_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
            files_created+=("$computers_file_out")
            echo "INFO: Créé $computers_file_out ($computer_count computers)" >&2
        fi
    fi
    
    local domain_sid=""
    
    if [ -f "$computers_file" ] && [ -s "$computers_file" ]; then
        local first_computer_sid=$(head -1 "$computers_file" | cut -d'|' -f3)
        domain_sid=$(echo "$first_computer_sid" | sed 's/-[0-9]*$//')
    elif [ -f "$users_file" ] && [ -s "$users_file" ]; then
        while IFS='|' read -r dn sam sid; do
            if [[ "$sid" =~ ^S-1-5-21- ]]; then
                domain_sid=$(echo "$sid" | sed 's/-[0-9]*$//')
                break
            fi
        done < "$users_file"
    elif [ -f "$groups_file" ] && [ -s "$groups_file" ]; then
        while IFS='|' read -r dn sam sid; do
            if [[ "$sid" =~ ^S-1-5-21- ]]; then
                domain_sid=$(echo "$sid" | sed 's/-[0-9]*$//')
                break
            fi
        done < "$groups_file"
    fi
    
    if [ -n "$domain_sid" ]; then
        local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
        local domain_dn="DC=$(echo $domain | sed 's/\./,DC=/g' | tr '[:lower:]' '[:upper:]')"
        
        local trusts_json="[]"
        local trusts_file="/tmp/bashhound_trusts_$$"
        if [ -f "$trusts_file" ] && [ -s "$trusts_file" ]; then
            local trust_objs=()
            while IFS='|' read -r dn name trust_partner trust_direction trust_type trust_attributes trust_sid; do
                if [ -n "$trust_partner" ]; then
                    local direction_name="Disabled"
                    case "$trust_direction" in
                        1) direction_name="Inbound" ;;
                        2) direction_name="Outbound" ;;
                        3) direction_name="Bidirectional" ;;
                    esac
                    
                    local type_name="ParentChild"
                    if [ -n "$trust_type" ]; then
                        case "$trust_type" in
                            1) type_name="ParentChild" ;;
                            2) type_name="CrossLink" ;;
                            3) type_name="External" ;;
                            4) type_name="Forest" ;;
                            *) type_name="Unknown" ;;
                        esac
                    fi
                    
                    local is_transitive="false"
                    local sid_filtering="false"
                    if [ -n "$trust_attributes" ]; then
                        if (( trust_attributes & 8 )); then
                            is_transitive="true"
                            type_name="Forest"
                        fi
                        if (( trust_attributes & 32 )); then
                            is_transitive="true"
                            type_name="Forest"
                        fi
                        if ! (( trust_attributes & 4 )); then
                            sid_filtering="true"
                        fi
                    fi
                    
                    local trust_partner_upper=$(echo "$trust_partner" | tr '[:lower:]' '[:upper:]')
                    
                    local sid_value="null"
                    if [ -n "$trust_sid" ] && [ "$trust_sid" != "null" ]; then
                        sid_value="\"$trust_sid\""
                    fi
                    
                    trust_objs+=("$(cat <<TRUSTEOF
{
  "TargetDomainName": "$trust_partner_upper",
  "TargetDomainSid": $sid_value,
  "IsTransitive": $is_transitive,
  "TrustDirection": "$direction_name",
  "TrustType": "$type_name",
  "SidFilteringEnabled": $sid_filtering
}
TRUSTEOF
)")
                fi
            done < "$trusts_file"
            
            if [ ${#trust_objs[@]} -gt 0 ]; then
                trusts_json="[$(IFS=,; echo "${trust_objs[*]}")]"
            fi
        fi
        
        local child_objects_json="[]"
        local child_objs=()
        
        local ous_file="/tmp/bashhound_ous_$$"
        if [ -f "$ous_file" ] && [ -s "$ous_file" ]; then
            while IFS='|' read -r dn name gplink blocks_inheritance description; do
                if [ -n "$dn" ]; then
                    local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                    local ou_guid=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                    child_objs+=("{\"ObjectIdentifier\":\"$ou_guid\",\"ObjectType\":\"OU\"}")
                fi
            done < "$ous_file"
        fi
        
        local containers_file="/tmp/bashhound_containers_$$"
        if [ -f "$containers_file" ] && [ -s "$containers_file" ]; then
            while IFS='|' read -r dn name description; do
                if [ -n "$dn" ]; then
                    local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                    local container_guid=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                    child_objs+=("{\"ObjectIdentifier\":\"$container_guid\",\"ObjectType\":\"Container\"}")
                fi
            done < "$containers_file"
        fi
        
        if [ ${#child_objs[@]} -gt 0 ]; then
            child_objects_json="[$(IFS=,; echo "${child_objs[*]}")]"
        fi
        
        # Parse GPLinks for domain
        local domain_gplinks_json="[]"
        local domains_file="/tmp/bashhound_domains_$$"
        if [ -f "$domains_file" ] && [ -s "$domains_file" ]; then
            local domain_gplink_raw=$(head -1 "$domains_file" | cut -d'|' -f2)
            if [ -n "$domain_gplink_raw" ] && [ "$domain_gplink_raw" != "null" ]; then
                domain_gplinks_json=$(parse_gplinks "$domain_gplink_raw")
            fi
        fi
        
        local domains_file_out="${output_prefix}_domains_${timestamp}.json"
        cat > "$domains_file_out" <<EOF
{
  "data": [
    {
      "ObjectIdentifier": "$domain_sid",
      "IsDeleted": false,
      "IsACLProtected": false,
      "Properties": {
        "domain": "$domain_upper",
        "name": "$domain_upper",
        "distinguishedname": "$domain_dn",
        "domainsid": "$domain_sid",
        "isaclprotected": false,
        "highvalue": true,
        "description": null,
        "whencreated": -1,
        "machineaccountquota": 10,
        "expirepasswordsonsmartcardonlyaccounts": true,
        "minpwdlength": 7,
        "pwdproperties": 1,
        "pwdhistorylength": 24,
        "lockoutthreshold": 0,
        "minpwdage": "1 day",
        "maxpwdage": "6 weeks",
        "lockoutduration": "10 minutes",
        "lockoutobservationwindow": -6000000000,
        "functionallevel": "Unknown",
        "collected": true
      },
      "Trusts": $trusts_json,
      "Aces": $(build_aces_json "$domain_sid"),
      "GPOChanges": {
        "LocalAdmins": [],
        "RemoteDesktopUsers": [],
        "DcomUsers": [],
        "PSRemoteUsers": [],
        "AffectedComputers": []
      },
      "ChildObjects": $child_objects_json,
      "Links": $domain_gplinks_json,
      "ContainedBy": null
    }
  ],
  "meta": {
    "methods": 0,
    "type": "domains",
    "count": 1,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
        files_created+=("$domains_file_out")
        echo "INFO: Créé $domains_file_out (1 domain)" >&2
    fi
    
    local gpos_file="/tmp/bashhound_gpos_$$"
    if [ -f "$gpos_file" ] && [ -s "$gpos_file" ]; then
        local gpos_data=()
        local gpo_count=0
        
        while IFS='|' read -r dn name displayname gpcpath guid; do
            if [ -n "$name" ]; then
                local domain_sid=$(get_domain_sid_from_collected)
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                
                local gpo_display_name="$displayname"
                if [ -z "$gpo_display_name" ]; then
                    gpo_display_name="$name"
                fi
                if [ -z "$gpo_display_name" ]; then
                    gpo_display_name=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1 | tr -d '{}')
                fi
                
                local gpo_name_upper=$(echo "$gpo_display_name@$domain_upper" | tr '[:lower:]' '[:upper:]')
                
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local gpcpath_escaped=$(echo "$gpcpath" | tr '[:lower:]' '[:upper:]' | sed 's/\\/\\\\/g')
                
                local aces_json=$(build_aces_json "$object_id")
                
                gpos_data+=("$(cat <<GPOEOF
{
  "ObjectIdentifier": "$object_id",
  "IsDeleted": false,
  "IsACLProtected": true,
  "Properties": {
    "domain": "$domain_upper",
    "name": "$gpo_name_upper",
    "distinguishedname": "$dn_upper",
    "domainsid": "$domain_sid",
    "highvalue": false,
    "description": null,
    "gpcpath": "$gpcpath_escaped",
    "whencreated": -1,
    "isaclprotected": true
  },
  "Aces": $aces_json
}
GPOEOF
)")
                ((gpo_count++))
            fi
        done < "$gpos_file"
        
        local gpos_file_out="${output_prefix}_gpos_${timestamp}.json"
        local gpos_json=$(IFS=,; echo "${gpos_data[*]}")
        cat > "$gpos_file_out" <<EOF
{
  "data": [
    $gpos_json
  ],
  "meta": {
    "methods": 0,
    "type": "gpos",
    "count": $gpo_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
        files_created+=("$gpos_file_out")
        echo "INFO: Créé $gpos_file_out ($gpo_count GPOs)" >&2
    fi
    
    local ous_file="/tmp/bashhound_ous_$$"
    if [ -f "$ous_file" ] && [ -s "$ous_file" ]; then
        local ous_data=()
        local ou_count=0
        
        while IFS='|' read -r dn name gplink blocks_inheritance description; do
            if [ -n "$name" ]; then
                local domain_sid=$(get_domain_sid_from_collected)
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local ou_name_upper=$(echo "$name@$domain_upper" | tr '[:lower:]' '[:upper:]')
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                
                local ou_guid=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                # Parse GPLinks properly (with IsEnforced detection)
                local links_json="[]"
                if [ -n "$gplink" ] && [ "$gplink" != "null" ]; then
                    links_json=$(parse_gplinks "$gplink")
                fi
                
                local desc_json="null"
                if [ -n "$description" ]; then
                    desc_json="\"$description\""
                fi
                
                local children_json=$(build_child_objects "$dn_upper")
                
                local aces_json=$(build_aces_json "$ou_guid")
                
                ous_data+=("$(cat <<OUEOF
{
  "ObjectIdentifier": "$ou_guid",
  "IsDeleted": false,
  "IsACLProtected": false,
  "Properties": {
    "domain": "$domain_upper",
    "name": "$ou_name_upper",
    "distinguishedname": "$dn_upper",
    "domainsid": "$domain_sid",
    "highvalue": false,
    "description": $desc_json,
    "blocksinheritance": $blocks_inheritance,
    "whencreated": -1,
    "isaclprotected": false
  },
  "Links": $links_json,
  "ChildObjects": $children_json,
  "Aces": $aces_json,
  "GPOChanges": {
    "LocalAdmins": [],
    "RemoteDesktopUsers": [],
    "DcomUsers": [],
    "PSRemoteUsers": [],
    "AffectedComputers": []
  }
}
OUEOF
)")
                ((ou_count++))
            fi
        done < "$ous_file"
        
        local ous_file_out="${output_prefix}_ous_${timestamp}.json"
        local ous_json=$(IFS=,; echo "${ous_data[*]}")
        cat > "$ous_file_out" <<EOF
{
  "data": [
    $ous_json
  ],
  "meta": {
    "methods": 0,
    "type": "ous",
    "count": $ou_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
        files_created+=("$ous_file_out")
        echo "INFO: Créé $ous_file_out ($ou_count OUs)" >&2
    fi
    
    local containers_file="/tmp/bashhound_containers_$$"
    if [ -f "$containers_file" ] && [ -s "$containers_file" ]; then
        local containers_data=()
        local container_count=0
        
        while IFS='|' read -r dn name description; do
            if [ -n "$name" ]; then
                local domain_sid=$(get_domain_sid_from_collected)
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local container_name_upper=$(echo "$name@$domain_upper" | tr '[:lower:]' '[:upper:]')
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                
                local container_guid=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local desc_json="null"
                if [ -n "$description" ]; then
                    desc_json=$(printf '%s' "$description" | jq -Rs .)
                fi
                
                local children_json=$(build_child_objects "$dn_upper")
                
                local aces_json=$(build_aces_json "$container_guid")
                
                containers_data+=("$(cat <<CONTAINEREOF
{
  "Properties": {
    "domain": "$domain_upper",
    "name": "$container_name_upper",
    "distinguishedname": "$dn_upper",
    "domainsid": "$domain_sid",
    "isaclprotected": false,
    "highvalue": false,
    "description": $desc_json,
    "whencreated": -1
  },
  "ChildObjects": $children_json,
  "Aces": $aces_json,
  "ContainedBy": null,
  "IsACLProtected": false,
  "IsDeleted": false,
  "ObjectIdentifier": "$container_guid"
}
CONTAINEREOF
)")
                ((container_count++))
            fi
        done < "$containers_file"
        
        local containers_file_out="${output_prefix}_containers_${timestamp}.json"
        local containers_json=$(IFS=,; echo "${containers_data[*]}")
        cat > "$containers_file_out" <<EOF
{
  "data": [
    $containers_json
  ],
  "meta": {
    "methods": 0,
    "type": "containers",
    "count": $container_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
        files_created+=("$containers_file_out")
        echo "INFO: Créé $containers_file_out ($container_count containers)" >&2
    fi
    
    local certtemplates_file="/tmp/bashhound_certtemplates_$$"
    if [ -f "$certtemplates_file" ] && [ -s "$certtemplates_file" ]; then
        local certtemplates_data=()
        local certtemplate_count=0
        
        while IFS='|' read -r dn name display_name cert_name_flag enrollment_flag private_key_flag eku app_policy ra_signature schema_version min_key_size when_created; do
            if [ -n "$dn" ] && [ -n "$name" ]; then
                [ -z "$when_created" ] && when_created="-1"
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local display_name_json="null"
                if [ -n "$display_name" ]; then
                    display_name="${display_name//\\/\\\\}"
                    display_name="${display_name//\"/\\\"}"
                    display_name_json="\"$display_name\""
                fi
                
                [ -z "$cert_name_flag" ] && cert_name_flag="0"
                [ -z "$enrollment_flag" ] && enrollment_flag="0"
                [ -z "$private_key_flag" ] && private_key_flag="0"
                [ -z "$ra_signature" ] && ra_signature="0"
                [ -z "$schema_version" ] && schema_version="1"
                [ -z "$min_key_size" ] && min_key_size="2048"
                
                local enrollee_supplies_subject="false"
                if (( cert_name_flag & 1 )); then
                    enrollee_supplies_subject="true"
                fi
                
                local requires_manager_approval="false"
                if (( enrollment_flag & 2 )); then
                    requires_manager_approval="true"
                fi
                
                local no_security_extension="false"
                if (( enrollment_flag & 524288 )); then
                    no_security_extension="true"
                fi
                
                local subject_alt_require_upn="false"
                if (( cert_name_flag & 33554432 )); then
                    subject_alt_require_upn="true"
                fi
                
                local authentication_enabled="false"
                if [[ "$eku" =~ 1\.3\.6\.1\.5\.5\.7\.3\.2 ]] || [[ "$eku" =~ 1\.3\.6\.1\.4\.1\.311\.20\.2\.2 ]]; then
                    authentication_enabled="true"
                fi
                
                local eku_json="[]"
                if [ -n "$eku" ]; then
                    local eku_array=()
                    IFS=',' read -ra eku_list <<< "$eku"
                    for oid in "${eku_list[@]}"; do
                        eku_array+=("\"$oid\"")
                    done
                    if [ ${#eku_array[@]} -gt 0 ]; then
                        eku_json="[$(IFS=,; echo "${eku_array[*]}")]"
                    fi
                fi
                
                local aces_json=$(build_aces_json_certtemplate "$object_id")
                local contained_by=$(resolve_contained_by "$dn_upper" "$domain_sid")
                
                certtemplates_data+=("$(cat <<CERTTEMPLATEEOF
{
  "ObjectIdentifier": "$object_id",
  "IsDeleted": false,
  "IsACLProtected": false,
  "Properties": {
    "domain": "$domain_upper",
    "name": "$(echo "$name" | tr '[:lower:]' '[:upper:]')",
    "displayname": $display_name_json,
    "distinguishedname": "$dn_upper",
    "domainsid": "$domain_sid",
    "isaclprotected": false,
    "description": null,
    "whencreated": $when_created,
    "certificatenameflag": $cert_name_flag,
    "enrollmentflag": $enrollment_flag,
    "privatekeyflag": $private_key_flag,
    "effectiveekus": $eku_json,
    "certificateapplicationpolicy": $eku_json,
    "ekus": $eku_json,
    "applicationpolicies": $eku_json,
    "authorizedsignatures": $ra_signature,
    "schemaversion": $schema_version,
    "validityperiod": "",
    "renewalperiod": "",
    "oid": "",
    "enrolleesuppliessubject": $enrollee_supplies_subject,
    "requiresmanagerapproval": $requires_manager_approval,
    "authenticationenabled": $authentication_enabled,
    "nosecurityextension": $no_security_extension,
    "subjectaltrequireupn": $subject_alt_require_upn,
    "issuancepolicies": []
  },
  "Aces": $aces_json,
  "ContainedBy": $contained_by
}
CERTTEMPLATEEOF
)")
                ((certtemplate_count++))
            fi
        done < "$certtemplates_file"
        
        if [ ${#certtemplates_data[@]} -gt 0 ]; then
            local certtemplates_file_out="${output_prefix}_certtemplates_${timestamp}.json"
            local certtemplates_json=$(IFS=,; echo "${certtemplates_data[*]}")
            cat > "$certtemplates_file_out" <<EOF
{
  "data": [
    $certtemplates_json
  ],
  "meta": {
    "methods": 0,
    "type": "certtemplates",
    "count": $certtemplate_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
            files_created+=("$certtemplates_file_out")
            echo "INFO: Créé $certtemplates_file_out ($certtemplate_count Certificate Templates)" >&2
        fi
    fi
    
    local enterprisecas_file="/tmp/bashhound_enterprisecas_$$"
    if [ -f "$enterprisecas_file" ] && [ -s "$enterprisecas_file" ]; then
        local enterprisecas_data=()
        local enterpriseca_count=0
        
        while IFS='|' read -r dn name display_name dns_hostname cert_templates when_created; do
            if [ -n "$dn" ] && [ -n "$name" ]; then
                [ -z "$when_created" ] && when_created="-1"
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local display_name_json="null"
                if [ -n "$display_name" ]; then
                    display_name="${display_name//\\/\\\\}"
                    display_name="${display_name//\"/\\\"}"
                    display_name_json="\"$display_name\""
                fi
                
                local dns_hostname_json="null"
                if [ -n "$dns_hostname" ]; then
                    dns_hostname_json="\"$(echo "$dns_hostname" | tr '[:lower:]' '[:upper:]')\""
                fi
                
                local enabled_templates_json="[]"
                if [ -n "$cert_templates" ]; then
                    local template_objs=()
                    IFS=',' read -ra template_array <<< "$cert_templates"
                    for template_name in "${template_array[@]}"; do
                        local template_name_upper=$(echo "$template_name" | tr '[:lower:]' '[:upper:]')
                        local template_dn="CN=${template_name_upper},CN=CERTIFICATE TEMPLATES,CN=PUBLIC KEY SERVICES,CN=SERVICES,CN=CONFIGURATION,$DOMAIN_DN"
                        local template_dn_upper=$(echo "$template_dn" | tr '[:lower:]' '[:upper:]')
                        local template_id=$(echo -n "$template_dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                        template_objs+=("{\"ObjectIdentifier\": \"$template_id\", \"ObjectType\": \"CertTemplate\"}")
                    done
                    if [ ${#template_objs[@]} -gt 0 ]; then
                        enabled_templates_json="[$(IFS=,; echo "${template_objs[*]}")]"
                    fi
                fi
                
                local aces_json=$(build_aces_json_enterpriseca "$object_id")
                local contained_by=$(resolve_contained_by "$dn_upper" "$domain_sid")
                
                enterprisecas_data+=("$(cat <<ENTERPRISECAEOF
{
  "ObjectIdentifier": "$object_id",
  "IsDeleted": false,
  "IsACLProtected": false,
  "Properties": {
    "domain": "$domain_upper",
    "name": "$(echo "$name" | tr '[:lower:]' '[:upper:]')@$domain_upper",
    "displayname": $display_name_json,
    "distinguishedname": "$dn_upper",
    "domainsid": "$domain_sid",
    "isaclprotected": false,
    "description": null,
    "whencreated": $when_created,
    "flags": "",
    "caname": "$(echo "$name" | tr '[:lower:]' '[:upper:]')",
    "dnshostname": $dns_hostname_json,
    "certthumbprint": "",
    "certname": "",
    "certchain": [],
    "hasbasicconstraints": false,
    "basicconstraintpathlength": 0,
    "unresolvedpublishedtemplates": [],
    "casecuritycollected": false,
    "enrollmentagentrestrictionscollected": false,
    "isuserspecifiessanenabledcollected": false,
    "roleseparationenabledcollected": false
  },
  "HostingComputer": "",
  "CARegistryData": {
    "CASecurity": {
      "Data": [],
      "Collected": false,
      "FailureReason": "Requires WinRM/RPC (not available via LDAP)"
    },
    "EnrollmentAgentRestrictions": {
      "Restrictions": [],
      "Collected": false,
      "FailureReason": "Requires WinRM/RPC (not available via LDAP)"
    },
    "IsUserSpecifiesSanEnabled": {
      "Value": false,
      "Collected": false,
      "FailureReason": "Requires WinRM/RPC (not available via LDAP)"
    },
    "RoleSeparationEnabled": {
      "Value": false,
      "Collected": false,
      "FailureReason": "Requires WinRM/RPC (not available via LDAP)"
    }
  },
  "EnabledCertTemplates": $enabled_templates_json,
  "Aces": $aces_json,
  "ContainedBy": $contained_by
}
ENTERPRISECAEOF
)")
                ((enterpriseca_count++))
            fi
        done < "$enterprisecas_file"
        
        if [ ${#enterprisecas_data[@]} -gt 0 ]; then
            local enterprisecas_file_out="${output_prefix}_enterprisecas_${timestamp}.json"
            local enterprisecas_json=$(IFS=,; echo "${enterprisecas_data[*]}")
            cat > "$enterprisecas_file_out" <<EOF
{
  "data": [
    $enterprisecas_json
  ],
  "meta": {
    "methods": 0,
    "type": "enterprisecas",
    "count": $enterpriseca_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
            files_created+=("$enterprisecas_file_out")
            echo "INFO: Créé $enterprisecas_file_out ($enterpriseca_count Enterprise CAs)" >&2
        fi
    fi
    
    # Export NTAuthStores
    local ntauthstores_file="/tmp/bashhound_ntauthstores_$$"
    if [ -f "$ntauthstores_file" ] && [ -s "$ntauthstores_file" ]; then
        local ntauthstores_data=()
        local ntauthstore_count=0
        
        while IFS='|' read -r dn name cert_thumbprints when_created; do
            if [ -n "$dn" ]; then
                [ -z "$when_created" ] && when_created="-1"
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                # Parse certificate thumbprints from collector
                local cert_thumbprints_json="[]"
                if [ -n "$cert_thumbprints" ]; then
                    local thumbprint_array=()
                    IFS=',' read -ra thumbprints <<< "$cert_thumbprints"
                    for thumbprint in "${thumbprints[@]}"; do
                        if [ -n "$thumbprint" ]; then
                            thumbprint_array+=("\"$thumbprint\"")
                        fi
                    done
                    if [ ${#thumbprint_array[@]} -gt 0 ]; then
                        cert_thumbprints_json="[$(IFS=,; echo "${thumbprint_array[*]}")]"
                    fi
                fi
                
                local aces_json=$(build_aces_json "$object_id")
                local contained_by=$(resolve_contained_by "$dn_upper" "$domain_sid")
                
                ntauthstores_data+=("$(cat <<NTAUTHEOF
{
  "ObjectIdentifier": "$object_id",
  "IsDeleted": false,
  "IsACLProtected": false,
  "Properties": {
    "domain": "$domain_upper",
    "name": "$(echo "$name@$domain_upper" | tr '[:lower:]' '[:upper:]')",
    "distinguishedname": "$dn_upper",
    "domainsid": "$domain_sid",
    "isaclprotected": false,
    "certthumbprints": $cert_thumbprints_json,
    "description": null,
    "whencreated": $when_created
  },
  "DomainSID": "$domain_sid",
  "Aces": $aces_json,
  "ContainedBy": $contained_by
}
NTAUTHEOF
)")
                ((ntauthstore_count++))
            fi
        done < "$ntauthstores_file"
        
        if [ ${#ntauthstores_data[@]} -gt 0 ]; then
            local ntauthstores_file_out="${output_prefix}_ntauthstores_${timestamp}.json"
            local ntauthstores_json=$(IFS=,; echo "${ntauthstores_data[*]}")
            cat > "$ntauthstores_file_out" <<EOF
{
  "data": [
    $ntauthstores_json
  ],
  "meta": {
    "methods": 0,
    "type": "ntauthstores",
    "count": $ntauthstore_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
            files_created+=("$ntauthstores_file_out")
            echo "INFO: Créé $ntauthstores_file_out ($ntauthstore_count NTAuth Stores)" >&2
        fi
    fi
    
    # Export AIACAs
    local aiacas_file="/tmp/bashhound_aiacas_$$"
    if [ -f "$aiacas_file" ] && [ -s "$aiacas_file" ]; then
        local aiacas_data=()
        local aiaca_count=0
        
        while IFS='|' read -r dn name cert_thumbprints has_cross_cert when_created; do
            if [ -n "$dn" ] && [ -n "$name" ]; then
                [ -z "$when_created" ] && when_created="-1"
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                # Parse certificate thumbprints from collector
                local cert_thumbprint=""
                local cert_chain_json="[]"
                if [ -n "$cert_thumbprints" ]; then
                    # Use first thumbprint as primary
                    cert_thumbprint=$(echo "$cert_thumbprints" | cut -d',' -f1)
                    
                    # Build cert chain array
                    local thumbprint_array=()
                    IFS=',' read -ra thumbprints <<< "$cert_thumbprints"
                    for tp in "${thumbprints[@]}"; do
                        if [ -n "$tp" ]; then
                            thumbprint_array+=("\"$tp\"")
                        fi
                    done
                    if [ ${#thumbprint_array[@]} -gt 0 ]; then
                        cert_chain_json="[$(IFS=,; echo "${thumbprint_array[*]}")]"
                    fi
                fi
                local cert_name="$cert_thumbprint"
                
                local cross_cert_pair_json="[]"
                local has_cross_cert_pair="$has_cross_cert"
                
                local aces_json=$(build_aces_json "$object_id")
                local contained_by=$(resolve_contained_by "$dn_upper" "$domain_sid")
                
                aiacas_data+=("$(cat <<AIACAEOF
{
  "ObjectIdentifier": "$object_id",
  "IsDeleted": false,
  "IsACLProtected": false,
  "Properties": {
    "domain": "$domain_upper",
    "name": "$(echo "$name@$domain_upper" | tr '[:lower:]' '[:upper:]')",
    "distinguishedname": "$dn_upper",
    "domainsid": "$domain_sid",
    "isaclprotected": false,
    "description": null,
    "whencreated": $when_created,
    "crosscertificatepair": $cross_cert_pair_json,
    "hascrosscertificatepair": $has_cross_cert_pair,
    "certthumbprint": "$cert_thumbprint",
    "certname": "$cert_name",
    "certchain": $cert_chain_json,
    "hasbasicconstraints": false,
    "basicconstraintpathlength": 0
  },
  "DomainSID": "$domain_sid",
  "Aces": $aces_json,
  "ContainedBy": $contained_by
}
AIACAEOF
)")
                ((aiaca_count++))
            fi
        done < "$aiacas_file"
        
        if [ ${#aiacas_data[@]} -gt 0 ]; then
            local aiacas_file_out="${output_prefix}_aiacas_${timestamp}.json"
            local aiacas_json=$(IFS=,; echo "${aiacas_data[*]}")
            cat > "$aiacas_file_out" <<EOF
{
  "data": [
    $aiacas_json
  ],
  "meta": {
    "methods": 0,
    "type": "aiacas",
    "count": $aiaca_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
            files_created+=("$aiacas_file_out")
            echo "INFO: Créé $aiacas_file_out ($aiaca_count AIA CAs)" >&2
        fi
    fi
    
    # Export RootCAs
    local rootcas_file="/tmp/bashhound_rootcas_$$"
    if [ -f "$rootcas_file" ] && [ -s "$rootcas_file" ]; then
        local rootcas_data=()
        local rootca_count=0
        
        while IFS='|' read -r dn name cert_thumbprints when_created; do
            if [ -n "$dn" ] && [ -n "$name" ]; then
                [ -z "$when_created" ] && when_created="-1"
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                # Parse certificate thumbprints from collector
                local cert_thumbprint=""
                local cert_chain_json="[]"
                if [ -n "$cert_thumbprints" ]; then
                    # Use first thumbprint as primary
                    cert_thumbprint=$(echo "$cert_thumbprints" | cut -d',' -f1)
                    
                    # Build cert chain array
                    local thumbprint_array=()
                    IFS=',' read -ra thumbprints <<< "$cert_thumbprints"
                    for tp in "${thumbprints[@]}"; do
                        if [ -n "$tp" ]; then
                            thumbprint_array+=("\"$tp\"")
                        fi
                    done
                    if [ ${#thumbprint_array[@]} -gt 0 ]; then
                        cert_chain_json="[$(IFS=,; echo "${thumbprint_array[*]}")]"
                    fi
                fi
                local cert_name="$cert_thumbprint"
                
                local aces_json=$(build_aces_json "$object_id")
                local contained_by=$(resolve_contained_by "$dn_upper" "$domain_sid")
                
                rootcas_data+=("$(cat <<ROOTCAEOF
{
  "ObjectIdentifier": "$object_id",
  "IsDeleted": false,
  "IsACLProtected": false,
  "Properties": {
    "domain": "$domain_upper",
    "name": "$(echo "$name@$domain_upper" | tr '[:lower:]' '[:upper:]')",
    "distinguishedname": "$dn_upper",
    "domainsid": "$domain_sid",
    "isaclprotected": false,
    "description": null,
    "whencreated": $when_created,
    "certthumbprint": "$cert_thumbprint",
    "certname": "$cert_name",
    "certchain": $cert_chain_json,
    "hasbasicconstraints": false,
    "basicconstraintpathlength": 0
  },
  "DomainSID": "$domain_sid",
  "Aces": $aces_json,
  "ContainedBy": $contained_by
}
ROOTCAEOF
)")
                ((rootca_count++))
            fi
        done < "$rootcas_file"
        
        if [ ${#rootcas_data[@]} -gt 0 ]; then
            local rootcas_file_out="${output_prefix}_rootcas_${timestamp}.json"
            local rootcas_json=$(IFS=,; echo "${rootcas_data[*]}")
            cat > "$rootcas_file_out" <<EOF
{
  "data": [
    $rootcas_json
  ],
  "meta": {
    "methods": 0,
    "type": "rootcas",
    "count": $rootca_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
            files_created+=("$rootcas_file_out")
            echo "INFO: Créé $rootcas_file_out ($rootca_count Root CAs)" >&2
        fi
    fi
    
    # Export IssuancePolicies
    local issuancepolicies_file="/tmp/bashhound_issuancepolicies_$$"
    if [ -f "$issuancepolicies_file" ] && [ -s "$issuancepolicies_file" ]; then
        local issuancepolicies_data=()
        local issuancepolicy_count=0
        
        while IFS='|' read -r dn name display_name cert_template_oid when_created; do
            if [ -n "$dn" ]; then
                [ -z "$when_created" ] && when_created="-1"
                
                # Filter out system issuance policies (CN < 100)
                # Extract CN number from DN (e.g., CN=400.xxx -> 400)
                local cn_number=$(echo "$dn" | grep -oP 'CN=\K[0-9]+' | head -1)
                if [ -n "$cn_number" ] && [ "$cn_number" -lt 100 ]; then
                    continue  # Skip system policies
                fi
                
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local domain_upper=$(echo "$domain" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local display_name_json="null"
                if [ -n "$display_name" ]; then
                    display_name="${display_name//\\/\\\\}"
                    display_name="${display_name//\"/\\\"}"
                    display_name_json="\"$display_name\""
                fi
                
                local cert_template_oid_json="null"
                if [ -n "$cert_template_oid" ]; then
                    cert_template_oid_json="\"$cert_template_oid\""
                fi
                
                local policy_name="$display_name"
                if [ -z "$policy_name" ]; then
                    policy_name="$name"
                fi
                
                local aces_json=$(build_aces_json "$object_id")
                
                issuancepolicies_data+=("$(cat <<ISSUANCEEOF
{
  "ObjectIdentifier": "$object_id",
  "IsDeleted": false,
  "IsACLProtected": false,
  "Properties": {
    "domain": "$domain_upper",
    "name": "$(echo "$policy_name@$domain_upper" | tr '[:lower:]' '[:upper:]')",
    "distinguishedname": "$dn_upper",
    "domainsid": "$domain_sid",
    "isaclprotected": false,
    "description": null,
    "whencreated": $when_created,
    "displayname": $display_name_json,
    "certtemplateoid": $cert_template_oid_json
  },
  "GroupLink": {
    "ObjectIdentifier": null,
    "ObjectType": "Base"
  },
  "Aces": $aces_json,
  "ContainedBy": null
}
ISSUANCEEOF
)")
                ((issuancepolicy_count++))
            fi
        done < "$issuancepolicies_file"
        
        if [ ${#issuancepolicies_data[@]} -gt 0 ]; then
            local issuancepolicies_file_out="${output_prefix}_issuancepolicies_${timestamp}.json"
            local issuancepolicies_json=$(IFS=,; echo "${issuancepolicies_data[*]}")
            cat > "$issuancepolicies_file_out" <<EOF
{
  "data": [
    $issuancepolicies_json
  ],
  "meta": {
    "methods": 0,
    "type": "issuancepolicies",
    "count": $issuancepolicy_count,
    "version": 6,
    "collectorversion": "BashHound-CE $version"
  }
}
EOF
            files_created+=("$issuancepolicies_file_out")
            echo "INFO: Créé $issuancepolicies_file_out ($issuancepolicy_count Issuance Policies)" >&2
        fi
    fi
    
    printf '%s\n' "${files_created[@]}"
}

get_domain_sid_from_collected() {
    local computers_file="/tmp/bashhound_computers_$$"
    if [ -f "$computers_file" ] && [ -s "$computers_file" ]; then
        local first_sid=$(head -1 "$computers_file" | cut -d'|' -f3)
        if [[ "$first_sid" =~ ^S-1-5-21- ]]; then
            echo "$first_sid" | sed 's/-[0-9]*$//'
            return
        fi
    fi
    
    local users_file="/tmp/bashhound_users_$$"
    if [ -f "$users_file" ] && [ -s "$users_file" ]; then
        local first_sid=$(head -1 "$users_file" | cut -d'|' -f3)
        if [[ "$first_sid" =~ ^S-1-5-21- ]]; then
            echo "$first_sid" | sed 's/-[0-9]*$//'
            return
        fi
    fi
    
    echo "S-1-5-21-0-0-0"
}

resolve_dn_to_sid_and_type() {
    local dn="$1"
    local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
    
    local users_file="/tmp/bashhound_users_$$"
    if [ -f "$users_file" ]; then
        while IFS='|' read -r collected_dn sam sid primary_gid; do
            local collected_dn_upper=$(echo "$collected_dn" | tr '[:lower:]' '[:upper:]')
            if [ "$collected_dn_upper" = "$dn_upper" ]; then
                echo "$sid|User"
                return
            fi
        done < "$users_file"
    fi
    
    local groups_file="/tmp/bashhound_groups_$$"
    if [ -f "$groups_file" ]; then
        while IFS='|' read -r collected_dn sam sid members; do
            local collected_dn_upper=$(echo "$collected_dn" | tr '[:lower:]' '[:upper:]')
            if [ "$collected_dn_upper" = "$dn_upper" ]; then
                echo "$sid|Group"
                return
            fi
        done < "$groups_file"
    fi
    
    local computers_file="/tmp/bashhound_computers_$$"
    if [ -f "$computers_file" ]; then
        while IFS='|' read -r collected_dn sam sid primary_gid; do
            local collected_dn_upper=$(echo "$collected_dn" | tr '[:lower:]' '[:upper:]')
            if [ "$collected_dn_upper" = "$dn_upper" ]; then
                echo "$sid|Computer"
                return
            fi
        done < "$computers_file"
    fi
    
    local fake_sid=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
    echo "$fake_sid|Unknown"
}

export_add_user() {
    local json="$1"
    local user_dn="$2"
    local sam_account="$3"
    local sid="$4"
    local enabled="$5"
    
    echo "$json" | jq --arg dn "$user_dn" \
                       --arg sam "$sam_account" \
                       --arg sid "$sid" \
                       --argjson enabled "$enabled" \
    '.data.users += [{
        "ObjectIdentifier": $sid,
        "Properties": {
            "name": ($sam + "@" + "DOMAIN"),
            "distinguishedname": $dn,
            "domain": "DOMAIN",
            "enabled": $enabled,
            "samaccountname": $sam
        },
        "Aces": [],
        "SPNTargets": [],
        "HasSIDHistory": [],
        "IsDeleted": false,
        "IsACLProtected": false
    }] | .meta.count += 1'
}

export_add_group() {
    local json="$1"
    local group_dn="$2"
    local sam_account="$3"
    local sid="$4"
    
    echo "$json" | jq --arg dn "$group_dn" \
                       --arg sam "$sam_account" \
                       --arg sid "$sid" \
    '.data.groups += [{
        "ObjectIdentifier": $sid,
        "Properties": {
            "name": ($sam + "@" + "DOMAIN"),
            "distinguishedname": $dn,
            "domain": "DOMAIN",
            "samaccountname": $sam
        },
        "Members": [],
        "Aces": [],
        "IsDeleted": false,
        "IsACLProtected": false
    }] | .meta.count += 1'
}

export_add_computer() {
    local json="$1"
    local computer_dn="$2"
    local sam_account="$3"
    local sid="$4"
    local enabled="$5"
    
    echo "$json" | jq --arg dn "$computer_dn" \
                       --arg sam "$sam_account" \
                       --arg sid "$sid" \
                       --argjson enabled "$enabled" \
    '.data.computers += [{
        "ObjectIdentifier": $sid,
        "Properties": {
            "name": $sam,
            "distinguishedname": $dn,
            "domain": "DOMAIN",
            "enabled": $enabled,
            "samaccountname": $sam
        },
        "LocalAdmins": [],
        "RemoteDesktopUsers": [],
        "DcomUsers": [],
        "PSRemoteUsers": [],
        "Aces": [],
        "AllowedToDelegate": [],
        "Sessions": [],
        "IsDeleted": false,
        "IsACLProtected": false
    }] | .meta.count += 1'
}

export_add_domain() {
    local json="$1"
    local domain_name="$2"
    local domain_sid="$3"
    
    echo "$json" | jq --arg name "$domain_name" \
                       --arg sid "$domain_sid" \
    '.data.domains += [{
        "ObjectIdentifier": $sid,
        "Properties": {
            "name": $name,
            "domain": $name,
            "distinguishedname": ("DC=" + ($name | split(".") | join(",DC=")))
        },
        "Trusts": [],
        "Aces": [],
        "ChildObjects": [],
        "Links": [],
        "IsDeleted": false,
        "IsACLProtected": false
    }] | .meta.count += 1'
}

export_add_gpo() {
    local json="$1"
    local gpo_guid="$2"
    local gpo_name="$3"
    
    echo "$json" | jq --arg guid "$gpo_guid" \
                       --arg name "$gpo_name" \
    '.data.gpos += [{
        "ObjectIdentifier": $guid,
        "Properties": {
            "name": ($name + "@" + "DOMAIN"),
            "domain": "DOMAIN"
        },
        "Aces": [],
        "IsDeleted": false,
        "IsACLProtected": false
    }] | .meta.count += 1'
}

export_add_ou() {
    local json="$1"
    local ou_guid="$2"
    local ou_dn="$3"
    
    echo "$json" | jq --arg guid "$ou_guid" \
                       --arg dn "$ou_dn" \
    '.data.ous += [{
        "ObjectIdentifier": $guid,
        "Properties": {
            "distinguishedname": $dn,
            "domain": "DOMAIN"
        },
        "Aces": [],
        "Links": [],
        "ChildObjects": [],
        "IsDeleted": false,
        "IsACLProtected": false
    }] | .meta.count += 1'
}

export_add_group_membership() {
    local json="$1"
    local group_sid="$2"
    local member_sid="$3"
    local member_type="$4"
    
    echo "$json" | jq --arg group_sid "$group_sid" \
                       --arg member_sid "$member_sid" \
                       --arg member_type "$member_type" \
    '(.data.groups[] | select(.ObjectIdentifier == $group_sid).Members) += [{
        "ObjectIdentifier": $member_sid,
        "ObjectType": $member_type
    }]'
}

export_add_ace() {
    local json="$1"
    local object_sid="$2"
    local object_type="$3"
    local principal_sid="$4"
    local principal_type="$5"
    local right_name="$6"
    local inherited="$7"
    
    local ace_json=$(jq -n \
        --arg principal_sid "$principal_sid" \
        --arg principal_type "$principal_type" \
        --arg right "$right_name" \
        --argjson inherited "$inherited" \
    '{
        "PrincipalSID": $principal_sid,
        "PrincipalType": $principal_type,
        "RightName": $right,
        "IsInherited": $inherited
    }')
    
    case "$object_type" in
        User)
            echo "$json" | jq --arg sid "$object_sid" \
                               --argjson ace "$ace_json" \
            '(.data.users[] | select(.ObjectIdentifier == $sid).Aces) += [$ace]'
            ;;
        Group)
            echo "$json" | jq --arg sid "$object_sid" \
                               --argjson ace "$ace_json" \
            '(.data.groups[] | select(.ObjectIdentifier == $sid).Aces) += [$ace]'
            ;;
        Computer)
            echo "$json" | jq --arg sid "$object_sid" \
                               --argjson ace "$ace_json" \
            '(.data.computers[] | select(.ObjectIdentifier == $sid).Aces) += [$ace]'
            ;;
        *)
            echo "$json"
            ;;
    esac
}
