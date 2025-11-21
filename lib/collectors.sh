#!/usr/bin/env bash

[[ -n "${_COLLECTORS_SH_LOADED:-}" ]] && return 0
readonly _COLLECTORS_SH_LOADED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$LIB_DIR/ldap.sh"
source "$LIB_DIR/ldap_parser.sh"
source "$LIB_DIR/acl_parser.sh"

DOMAIN_NAME=""
DOMAIN_DN=""
DOMAIN_SID=""

COLLECTED_USERS="/tmp/bashhound_users_$$"
COLLECTED_GROUPS="/tmp/bashhound_groups_$$"
COLLECTED_COMPUTERS="/tmp/bashhound_computers_$$"
COLLECTED_DOMAINS="/tmp/bashhound_domains_$$"
COLLECTED_GPOS="/tmp/bashhound_gpos_$$"
COLLECTED_OUS="/tmp/bashhound_ous_$$"
COLLECTED_CONTAINERS="/tmp/bashhound_containers_$$"
COLLECTED_TRUSTS="/tmp/bashhound_trusts_$$"
COLLECTED_ACES="/tmp/bashhound_aces_$$"

trap 'rm -f "$COLLECTED_USERS" "$COLLECTED_GROUPS" "$COLLECTED_COMPUTERS" "$COLLECTED_DOMAINS" "$COLLECTED_GPOS" "$COLLECTED_OUS" "$COLLECTED_CONTAINERS" "$COLLECTED_TRUSTS" "$COLLECTED_ACES" 2>/dev/null' EXIT

collector_init_domain() {
    local domain="$1"
    DOMAIN_NAME="$domain"
    
    DOMAIN_DN=$(echo "$domain" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
    
    > "$COLLECTED_ACES"
    
    echo "INFO: Domaine initialisé - $DOMAIN_NAME ($DOMAIN_DN)" >&2
}

collect_domain_info() {
    echo "INFO: Collecte des informations du domaine..." >&2
    
    local results=$(ldap_search "$DOMAIN_DN" 0 "(objectClass=domain)" "objectSid,name,distinguishedName,nTSecurityDescriptor")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucune information de domaine trouvée" >&2
        return 1
    fi
    
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local sid=$(extract_sid_from_response "$line")
            if [ -n "$sid" ]; then
                DOMAIN_SID="$sid"
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$sid|Domain|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
            fi
        fi
    done <<< "$results"
    
    echo "$results"
}

collect_users() {
    echo "INFO: Collecte des utilisateurs..." >&2
    
    local filter="(objectClass=user)"
    local attributes="distinguishedName,sAMAccountName,objectSid,primaryGroupID,userAccountControl,servicePrincipalName,lastLogon,lastLogontimestamp,pwdLastSet,whenCreated,description,adminCount,nTSecurityDescriptor"
    
    local results=$(ldap_search "$DOMAIN_DN" 2 "$filter" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucun utilisateur trouvé" >&2
        return 0
    fi
    
    > "$COLLECTED_USERS"
    
    local count=0
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local sam=$(extract_sam_from_response "$line")
            local sid=$(extract_sid_from_response "$line")
            local primary_gid=$(extract_primary_group_id "$line")
            
            local description=$(extract_attribute_value "$line" "description")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            local last_logon=$(extract_filetime_timestamp "$line" "lastLogon")
            local last_logon_ts=$(extract_filetime_timestamp "$line" "lastLogontimestamp")
            local pwd_last_set=$(extract_filetime_timestamp "$line" "pwdLastSet")
            local uac=$(extract_uac_flags "$line")
            local admin_count=$(extract_attribute_value "$line" "adminCount")
            
            local spns=$(extract_multi_valued_attribute "$line" "servicePrincipalName")
            
            if [ "$admin_count" = "1" ]; then
                admin_count="1"
            else
                admin_count="0"
            fi
            
            if [ -z "$sam" ] && [ -n "$dn" ]; then
                sam=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
            fi
            
            if [[ "$sam" =~ \$$ ]]; then
                continue
            fi
            
            if [ -z "$sid" ]; then
                sid="S-1-5-21-0-0-$count"
            fi
            
            if [ -n "$dn" ] && [ -n "$sid" ]; then
                echo "$dn|$sam|$sid|$primary_gid|$description|$when_created|$last_logon|$last_logon_ts|$pwd_last_set|$uac|$admin_count|$spns" >> "$COLLECTED_USERS"
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Found $(echo "$aces" | wc -l) ACEs for user $sam" >&2
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$sid|User|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                else
                    [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: No ACEs found for user $sam (line length: ${#line})" >&2
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count utilisateurs collectés et parsés" >&2
}

collect_groups() {
    echo "INFO: Collecte des groupes..." >&2
    
    local filter="(objectClass=group)"
    local attributes="distinguishedName,sAMAccountName,objectSid,member,memberOf,adminCount,description,whenCreated,nTSecurityDescriptor"
    
    local results=$(ldap_search "$DOMAIN_DN" 2 "$filter" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucun groupe trouvé" >&2
        return 0
    fi
    
    > "$COLLECTED_GROUPS"
    
    local count=0
    local total_members=0
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local sam=$(extract_sam_from_response "$line")
            local sid=$(extract_sid_from_response "$line")
            local members=$(extract_members_from_response "$line")
            
            local description=$(extract_attribute_value "$line" "description")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            local admin_count=$(extract_attribute_value "$line" "adminCount")
            
            if [ "$admin_count" = "1" ]; then
                admin_count="1"
            else
                admin_count="0"
            fi
            
            if [ -z "$sam" ] && [ -n "$dn" ]; then
                sam=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
            fi
            
            if [ -z "$sid" ]; then
                sid="S-1-5-21-0-0-$count"
            fi
            
            if [ -n "$members" ]; then
                local member_count=$(echo "$members" | tr '|' '\n' | wc -l)
                total_members=$((total_members + member_count))
            fi
            
            if [ -n "$dn" ] && [ -n "$sid" ]; then
                echo "$dn|$sam|$sid|$members|$description|$when_created|$admin_count" >> "$COLLECTED_GROUPS"
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$sid|Group|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count groupes collectés, $total_members relations membres" >&2
}

collect_computers() {
    echo "INFO: Collecte des ordinateurs..." >&2
    
    local filter="(objectClass=computer)"
    local attributes="distinguishedName,sAMAccountName,dNSHostName,objectSid,operatingSystem,servicePrincipalName,userAccountControl,lastLogon,lastLogontimestamp,pwdLastSet,whenCreated,description,primaryGroupID,nTSecurityDescriptor"
    
    local results=$(ldap_search "$DOMAIN_DN" 2 "$filter" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucun ordinateur trouvé" >&2
        return 0
    fi
    
    > "$COLLECTED_COMPUTERS"
    
    local count=0
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local sam=$(extract_sam_from_response "$line")
            local sid=$(extract_sid_from_response "$line")
            local primary_gid=$(extract_primary_group_id "$line")
            
            local description=$(extract_attribute_value "$line" "description")
            local operating_system=$(extract_attribute_value "$line" "operatingSystem")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            local last_logon=$(extract_filetime_timestamp "$line" "lastLogon")
            local last_logon_ts=$(extract_filetime_timestamp "$line" "lastLogontimestamp")
            local pwd_last_set=$(extract_filetime_timestamp "$line" "pwdLastSet")
            local uac=$(extract_uac_flags "$line")
            
            local spns=$(extract_multi_valued_attribute "$line" "servicePrincipalName")
            
            if [ -z "$sam" ] && [ -n "$dn" ]; then
                sam=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
            fi
            
            if [ -z "$sid" ]; then
                sid="S-1-5-21-0-0-$count"
            fi
            
            if [ -n "$dn" ] && [ -n "$sid" ]; then
                echo "$dn|$sam|$sid|$primary_gid|$description|$operating_system|$when_created|$last_logon|$last_logon_ts|$pwd_last_set|$uac|$spns" >> "$COLLECTED_COMPUTERS"
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$sid|Computer|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count ordinateurs collectés et parsés" >&2
}

collect_gpos() {
    echo "INFO: Collecte des GPOs..." >&2
    
    local gpo_container="CN=Policies,CN=System,$DOMAIN_DN"
    local filter="(objectClass=groupPolicyContainer)"
    local attributes="distinguishedName,name,displayName,gPCFileSysPath,whenCreated,description,nTSecurityDescriptor"
    
    local results=$(ldap_search "$gpo_container" 2 "$filter" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucune GPO trouvée" >&2
        return 0
    fi
    
    > "$COLLECTED_GPOS"
    
    local count=0
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local name=$(extract_attribute_value "$line" "name")
            local displayname=$(extract_attribute_value "$line" "displayName")
            local gpcpath=$(extract_attribute_value "$line" "gPCFileSysPath")
            
            local guid=$(echo "$dn" | grep -oP 'CN=\{\K[^}]+' | head -1)
            
            if [ -z "$name" ] && [ -n "$dn" ]; then
                name=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
            fi
            
            if [ -n "$dn" ]; then
                echo "$dn|$name|$displayname|$gpcpath|$guid" >> "$COLLECTED_GPOS"
                
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$object_id|GPO|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count GPOs collectées et parsées" >&2
}

collect_ous() {
    echo "INFO: Collecte des OUs..." >&2
    
    local filter="(objectClass=organizationalUnit)"
    local attributes="distinguishedName,name,gPLink,gPOptions,description,whenCreated,nTSecurityDescriptor"
    
    local results=$(ldap_search "$DOMAIN_DN" 2 "$filter" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucune OU trouvée" >&2
        return 0
    fi
    
    > "$COLLECTED_OUS"
    
    local count=0
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local name=$(extract_attribute_value "$line" "name")
            local gplink=$(extract_attribute_value "$line" "gPLink")
            local gpoptions=$(extract_attribute_value "$line" "gPOptions")
            local description=$(extract_attribute_value "$line" "description")
            
            if [ -z "$name" ] && [ -n "$dn" ]; then
                name=$(echo "$dn" | grep -oP 'OU=\K[^,]+' | head -1)
            fi
            
            local blocks_inheritance="false"
            if [ "$gpoptions" = "1" ]; then
                blocks_inheritance="true"
            fi
            
            if [ -n "$dn" ]; then
                echo "$dn|$name|$gplink|$blocks_inheritance|$description" >> "$COLLECTED_OUS"
                
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$object_id|OU|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count OUs collectées et parsées" >&2
}

collect_trusts() {
    echo "INFO: Collecte des trusts..." >&2
    
    local trust_container="CN=System,$DOMAIN_DN"
    local filter="(objectClass=trustedDomain)"
    local attributes="distinguishedName,name,trustPartner,trustDirection,trustType,trustAttributes,securityIdentifier"
    
    local results=$(ldap_search "$trust_container" 2 "$filter" "$attributes")
    
    if [ -z "$results" ]; then
        echo "INFO: Aucun trust trouvé" >&2
        return 0
    fi
    
    > "$COLLECTED_TRUSTS"
    
    local count=0
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local name=$(extract_attribute_value "$line" "name")
            local trust_partner=$(extract_attribute_value "$line" "trustPartner")
            local trust_direction=$(extract_attribute_value "$line" "trustDirection")
            local trust_type=$(extract_attribute_value "$line" "trustType")
            local trust_attributes=$(extract_attribute_value "$line" "trustAttributes")
            local sid=$(extract_sid_from_response "$line")
            
            if [ -z "$name" ] && [ -n "$dn" ]; then
                name=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
            fi
            
            if [ -n "$trust_partner" ]; then
                echo "$dn|$name|$trust_partner|$trust_direction|$trust_type|$trust_attributes|$sid" >> "$COLLECTED_TRUSTS"
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count trusts collectés et parsés" >&2
}

collect_containers() {
    echo "INFO: Collecte des containers..." >&2
    
    local container_names=(
        "CN=Users"
        "CN=Computers"
        "CN=System"
        "CN=ForeignSecurityPrincipals"
        "CN=Program Data"
        "CN=Managed Service Accounts"
    )
    
    > "$COLLECTED_CONTAINERS"
    
    local count=0
    
    for container_base in "${container_names[@]}"; do
        local container_dn="${container_base},$DOMAIN_DN"
        local filter="(objectClass=container)"
        local attributes="distinguishedName,name,description,whenCreated,nTSecurityDescriptor"
        
        local results=$(ldap_search "$container_dn" 0 "(objectClass=*)" "$attributes")
        
        if [ -n "$results" ]; then
            while IFS= read -r line; do
                if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
                    local dn=$(extract_dn_from_response "$line")
                    local name=$(extract_attribute_value "$line" "name")
                    local description=$(extract_attribute_value "$line" "description")
                    
                    if [ -z "$name" ] && [ -n "$dn" ]; then
                        name=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
                    fi
                    
                    if [ -n "$dn" ]; then
                        echo "$dn|$name|$description" >> "$COLLECTED_CONTAINERS"
                        
                        local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                        local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                        
                        local aces=$(extract_aces_from_ldap_response "$line")
                        if [ -n "$aces" ]; then
                            while IFS='|' read -r principal_sid right_name is_inherited; do
                                if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                                    echo "$object_id|Container|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                                fi
                            done <<< "$aces"
                        fi
                        
                        ((count++))
                    fi
                fi
            done <<< "$results"
        fi
        
        local sub_results=$(ldap_search "$container_dn" 1 "(objectClass=container)" "$attributes")
        
        if [ -n "$sub_results" ]; then
            while IFS= read -r line; do
                if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
                    local dn=$(extract_dn_from_response "$line")
                    local name=$(extract_attribute_value "$line" "name")
                    local description=$(extract_attribute_value "$line" "description")
                    
                    if [ -z "$name" ] && [ -n "$dn" ]; then
                        name=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
                    fi
                    
                    if [ -n "$dn" ]; then
                        echo "$dn|$name|$description" >> "$COLLECTED_CONTAINERS"
                        
                        local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                        local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                        
                        local aces=$(extract_aces_from_ldap_response "$line")
                        if [ -n "$aces" ]; then
                            while IFS='|' read -r principal_sid right_name is_inherited; do
                                if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                                    echo "$object_id|Container|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                                fi
                            done <<< "$aces"
                        fi
                        
                        ((count++))
                    fi
                fi
            done <<< "$sub_results"
        fi
    done
    
    echo "INFO: $count containers collectés et parsés" >&2
}
