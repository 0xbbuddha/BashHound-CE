#!/usr/bin/env bash

################################################################################
# collectors.sh - Active Directory object collectors
#
# This module queries LDAP to collect all Active Directory objects:
# - Users (objectClass=user)
# - Groups (objectClass=group) + memberships
# - Computers (objectClass=computer)
# - Domains (objectClass=domain) + GPLinks
# - GPOs (objectClass=groupPolicyContainer)
# - OUs (objectClass=organizationalUnit) + GPLinks
# - Containers (objectClass=container)
# - Trusts (objectClass=trustedDomain)
# - ACLs/ACEs (nTSecurityDescriptor attribute)
#
# Each collector function:
# 1. Performs LDAP search with specific filter
# 2. Parses hex responses with ldap_parser.sh functions
# 3. Stores results in temporary files for later export
#
# Temporary files are pipe-delimited (|) format for easy parsing.
################################################################################

[[ -n "${_COLLECTORS_SH_LOADED:-}" ]] && return 0
readonly _COLLECTORS_SH_LOADED=1

# Load required libraries
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$LIB_DIR/ldap.sh"          # LDAP protocol functions
source "$LIB_DIR/ldap_parser.sh"    # LDAP response parsing
source "$LIB_DIR/acl_parser.sh"     # Security Descriptor / ACL parsing

# -------------------------------------------------------------------------
# DOMAIN STATE VARIABLES
# -------------------------------------------------------------------------
DOMAIN_NAME=""      # Domain name (e.g., domain.local)
DOMAIN_DN=""        # Domain DN (e.g., DC=domain,DC=local)
DOMAIN_SID=""       # Domain SID (e.g., S-1-5-21-...)

# -------------------------------------------------------------------------
# TEMPORARY FILES FOR COLLECTED DATA
# Each file stores pipe-delimited data for one object type
# -------------------------------------------------------------------------
COLLECTED_USERS="/tmp/bashhound_users_$$"
COLLECTED_GROUPS="/tmp/bashhound_groups_$$"
COLLECTED_COMPUTERS="/tmp/bashhound_computers_$$"
COLLECTED_DOMAINS="/tmp/bashhound_domains_$$"
COLLECTED_GPOS="/tmp/bashhound_gpos_$$"
COLLECTED_OUS="/tmp/bashhound_ous_$$"
COLLECTED_CONTAINERS="/tmp/bashhound_containers_$$"
COLLECTED_TRUSTS="/tmp/bashhound_trusts_$$"
COLLECTED_ACES="/tmp/bashhound_aces_$$"
COLLECTED_CERTTEMPLATES="/tmp/bashhound_certtemplates_$$"
COLLECTED_ENTERPRISECAS="/tmp/bashhound_enterprisecas_$$"
COLLECTED_NTAUTHSTORES="/tmp/bashhound_ntauthstores_$$"
COLLECTED_AIACAS="/tmp/bashhound_aiacas_$$"
COLLECTED_ROOTCAS="/tmp/bashhound_rootcas_$$"
COLLECTED_ISSUANCEPOLICIES="/tmp/bashhound_issuancepolicies_$$"

# Export variables for export_ce.sh to use (needed for ContainedBy resolution)
export COLLECTED_OUS COLLECTED_CONTAINERS COLLECTED_CERTTEMPLATES COLLECTED_ENTERPRISECAS COLLECTED_NTAUTHSTORES COLLECTED_AIACAS COLLECTED_ROOTCAS COLLECTED_ISSUANCEPOLICIES

# Cleanup temporary files on script exit
# Note: Cleanup is now handled by the main script after export to avoid
# premature deletion before export_ce.sh can read OUs/Containers
# trap 'rm -f "$COLLECTED_USERS" "$COLLECTED_GROUPS" "$COLLECTED_COMPUTERS" "$COLLECTED_DOMAINS" "$COLLECTED_GPOS" "$COLLECTED_OUS" "$COLLECTED_CONTAINERS" "$COLLECTED_TRUSTS" "$COLLECTED_ACES" 2>/dev/null' EXIT

################################################################################
# collector_init_domain - Initialize domain for collection
#
# Args:
#   $1 - domain: Domain name (e.g., domain.local)
#
# Side effects:
#   Sets DOMAIN_NAME, DOMAIN_DN
#   Initializes COLLECTED_ACES file
################################################################################
collector_init_domain() {
    local domain="$1"
    DOMAIN_NAME="$domain"
    
    # Convert domain.local -> DC=domain,DC=local
    DOMAIN_DN=$(echo "$domain" | sed 's/\./,DC=/g' | sed 's/^/DC=/')
    
    # Initialize ACEs collection file
    > "$COLLECTED_ACES"
    
    echo "INFO: Domaine initialisé - $DOMAIN_NAME ($DOMAIN_DN)" >&2
}

################################################################################
# collect_domain_info - Collect domain object information
#
# Queries the domain object itself to get:
# - Domain SID
# - Domain GPLinks
# - Domain ACLs
#
# Results stored in: COLLECTED_DOMAINS, COLLECTED_ACES, DOMAIN_SID (global)
################################################################################
collect_domain_info() {
    echo "INFO: Collecte des informations du domaine..." >&2
    
    local results=$(ldap_search "$DOMAIN_DN" 0 "(objectClass=domain)" "objectSid,name,distinguishedName,gPLink,nTSecurityDescriptor")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucune information de domaine trouvée" >&2
        return 1
    fi
    
    > "$COLLECTED_DOMAINS"
    
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local sid=$(extract_sid_from_response "$line")
            local gplink=$(extract_attribute_value "$line" "gPLink")
            
            if [ -n "$sid" ]; then
                DOMAIN_SID="$sid"
                
                # Store domain gplink for export
                echo "$DOMAIN_DN|$gplink" >> "$COLLECTED_DOMAINS"
                
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

################################################################################
# collect_users - Collect all user objects from AD
#
# LDAP Filter: (objectClass=user)
# Attributes: DN, sAMAccountName, objectSid, primaryGroupID, userAccountControl,
#             servicePrincipalName, timestamps, description, adminCount, ACLs
#
# Results stored in: COLLECTED_USERS, COLLECTED_ACES
################################################################################
collect_users() {
    echo "INFO: Collecte des utilisateurs..." >&2
    
    local filter="(objectClass=user)"
    local attributes="distinguishedName,sAMAccountName,objectSid,primaryGroupID,userAccountControl,servicePrincipalName,lastLogon,lastLogonTimestamp,pwdLastSet,whenCreated,description,adminCount,displayName,mail,title,homeDirectory,scriptPath,msDS-SupportedEncryptionTypes,sIDHistory,msDS-AllowedToDelegateTo,isDeleted,nTSecurityDescriptor"
    
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
            
            # DEBUG: Save first user response for analysis
            if [ "$count" -eq 0 ] && [ -n "$sam" ]; then
                echo "$line" > "/tmp/bashhound_debug_user_response.hex"
                [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: Saved user response to /tmp/bashhound_debug_user_response.hex" >&2
            fi
            
            local description=$(extract_attribute_value "$line" "description")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            local last_logon=$(extract_filetime_timestamp "$line" "lastLogon")
            local last_logon_ts=$(extract_filetime_timestamp "$line" "lastLogonTimestamp")
            local pwd_last_set=$(extract_filetime_timestamp "$line" "pwdLastSet")
            local uac=$(extract_uac_flags "$line")
            
            # DEBUG: Log extracted values
            if [ "$count" -eq 0 ] && [ -n "$sam" ]; then
                [ "$LDAP_DEBUG" = "true" ] && echo "DEBUG: User $sam - whenCreated=$when_created, primaryGID=$primary_gid, UAC=$uac" >&2
            fi
            local admin_count=$(extract_attribute_value "$line" "adminCount")
            
            # Extract additional user attributes
            local display_name=$(extract_attribute_value "$line" "displayName")
            local email=$(extract_attribute_value "$line" "mail")
            local title=$(extract_attribute_value "$line" "title")
            local home_directory=$(extract_attribute_value "$line" "homeDirectory")
            local logon_script=$(extract_attribute_value "$line" "scriptPath")
            local supported_enc_types=$(extract_attribute_value "$line" "msDS-SupportedEncryptionTypes")
            local allowed_to_delegate=$(extract_multi_valued_attribute "$line" "msDS-AllowedToDelegateTo")
            local sid_history=$(extract_sidhistory "$line")
            local is_deleted=$(extract_attribute_value "$line" "isDeleted")
            local is_acl_protected=$(extract_is_acl_protected "$line")
            
            local spns=$(extract_multi_valued_attribute "$line" "servicePrincipalName")
            
            if [ "$admin_count" = "1" ]; then
                admin_count="1"
            else
                admin_count="0"
            fi
            
            if [ -z "$sam" ] && [ -n "$dn" ]; then
                sam=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
            fi
            
            # Skip computer accounts (UAC flag 0x1000 = WORKSTATION_TRUST_ACCOUNT)
            # But keep trust accounts like "domain-ext$" which are important for BloodHound
            if [ -n "$uac" ] && (( uac & 0x1000 )); then
                continue
            fi
            
            # Skip objects in OU=Domain Controllers (they're collected as computers)
            if [[ "$dn" =~ OU=Domain\ Controllers, ]]; then
                continue
            fi
            
            if [ -z "$sid" ]; then
                sid="S-1-5-21-0-0-$count"
            fi
            
            if [ -n "$dn" ] && [ -n "$sid" ]; then
                echo "$dn|$sam|$sid|$primary_gid|$description|$when_created|$last_logon|$last_logon_ts|$pwd_last_set|$uac|$admin_count|$spns|$display_name|$email|$title|$home_directory|$logon_script|$supported_enc_types|$allowed_to_delegate|$sid_history|$is_deleted|$is_acl_protected" >> "$COLLECTED_USERS"
                
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
    
    # Add well-known SIDs as synthetic users (like RustHound does)
    # These are system accounts that don't exist in LDAP but are important for BloodHound
    local domain_upper=$(echo "$DOMAIN_NAME" | tr '[:lower:]' '[:upper:]')
    
    # NT AUTHORITY (S-1-5-20 = NETWORK SERVICE)
    # Format: dn|sam|sid|primary_gid|description|when_created|last_logon|last_logon_ts|pwd_last_set|uac|admin_count|spns|display_name|email|title|home_directory|logon_script|supported_enc_types|allowed_to_delegate|sid_history|is_deleted|is_acl_protected
    echo "|NT AUTHORITY|${domain_upper}-S-1-5-20|0||-1|-1|-1|-1|0|0|||||||0|||false|false" >> "$COLLECTED_USERS"
    ((count++))
    
    echo "INFO: $count utilisateurs collectés et parsés" >&2
}

################################################################################
# collect_groups - Collect all group objects from AD
#
# LDAP Filter: (objectClass=group)
# Attributes: DN, sAMAccountName, objectSid, member, adminCount, ACLs
#
# Results stored in: COLLECTED_GROUPS, COLLECTED_ACES
################################################################################
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
    local attributes="distinguishedName,sAMAccountName,dNSHostName,objectSid,operatingSystem,servicePrincipalName,userAccountControl,lastLogon,lastLogonTimestamp,pwdLastSet,whenCreated,description,primaryGroupID,nTSecurityDescriptor"
    
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
            local last_logon_ts=$(extract_filetime_timestamp "$line" "lastLogonTimestamp")
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
    
    > "$COLLECTED_CONTAINERS"
    
    local count=0
    local attributes="distinguishedName,name,description,whenCreated,nTSecurityDescriptor"
    
    # Collect containers from Domain NC (DC=domain,DC=tld)
    # Scope 2 = subtree search (recursive)
    local domain_results=$(ldap_search "$DOMAIN_DN" 2 "(objectClass=container)" "$attributes")
    
    if [ -n "$domain_results" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
                local dn=$(extract_dn_from_response "$line")
                local name=$(extract_attribute_value "$line" "name")
                local description=$(extract_attribute_value "$line" "description")
                
                if [ -z "$name" ] && [ -n "$dn" ]; then
                    name=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
                fi
                
                # Exclude system containers that are not useful for BloodHound analysis  
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                if [[ "$dn_upper" =~ ,CN=OPERATIONS, ]] || \
                   [[ "$dn_upper" =~ ,CN=LOSTANDFOUND, ]] || \
                   [[ "$dn_upper" =~ ,CN=DELETED.OBJECTS, ]] || \
                   [[ "$dn_upper" =~ ,CN=NTDS.QUOTAS, ]]; then
                    continue
                fi
                
                if [ -n "$dn" ]; then
                    echo "$dn|$name|$description" >> "$COLLECTED_CONTAINERS"
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
        done <<< "$domain_results"
    fi
    
    # Collect containers from Configuration NC (CN=Configuration,DC=domain,DC=tld)
    # This includes AD CS containers (Certificate Templates, Enrollment Services, etc.)
    local config_dn="CN=Configuration,$DOMAIN_DN"
    local config_results=$(ldap_search "$config_dn" 2 "(objectClass=container)" "$attributes")
    
    if [ -n "$config_results" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
                local dn=$(extract_dn_from_response "$line")
                local name=$(extract_attribute_value "$line" "name")
                local description=$(extract_attribute_value "$line" "description")
                
                if [ -z "$name" ] && [ -n "$dn" ]; then
                    name=$(echo "$dn" | grep -oP 'CN=\K[^,]+' | head -1)
                fi
                
                # Exclude system containers that are not useful for BloodHound analysis  
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                if [[ "$dn_upper" =~ ,CN=OPERATIONS, ]] || \
                   [[ "$dn_upper" =~ ,CN=LOSTANDFOUND, ]] || \
                   [[ "$dn_upper" =~ ,CN=DELETED.OBJECTS, ]] || \
                   [[ "$dn_upper" =~ ,CN=NTDS.QUOTAS, ]]; then
                    continue
                fi
                
                if [ -n "$dn" ]; then
                    echo "$dn|$name|$description" >> "$COLLECTED_CONTAINERS"
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
        done <<< "$config_results"
    fi
    
    echo "INFO: $count containers collectés et parsés" >&2
}

################################################################################
# collect_cert_templates - Collect AD CS Certificate Templates
#
# Queries CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration
# for all pKICertificateTemplate objects.
#
# Attributes collected:
# - distinguishedName, name, displayName
# - msPKI-Certificate-Name-Flag (bitmask for ESC1 detection)
# - msPKI-Enrollment-Flag (bitmask for manager approval)
# - msPKI-Private-Key-Flag (bitmask for key archival)
# - pKIExtendedKeyUsage (OIDs for certificate usage)
# - msPKI-Certificate-Application-Policy
# - msPKI-RA-Signature (number of signatures required)
# - pKIExpirationPeriod, pKIOverlapPeriod
# - nTSecurityDescriptor (ACLs)
#
# Results stored in: COLLECTED_CERTTEMPLATES, COLLECTED_ACES
################################################################################
collect_cert_templates() {
    echo "INFO: Collecte des Certificate Templates..." >&2
    
    local config_dn="CN=Configuration,$DOMAIN_DN"
    local pki_dn="CN=Public Key Services,CN=Services,$config_dn"
    local templates_dn="CN=Certificate Templates,$pki_dn"
    
    local attributes="distinguishedName,name,displayName,msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-Private-Key-Flag,pKIExtendedKeyUsage,msPKI-Certificate-Application-Policy,msPKI-RA-Signature,msPKI-Template-Schema-Version,pKIExpirationPeriod,pKIOverlapPeriod,msPKI-Minimal-Key-Size,whenCreated,nTSecurityDescriptor"
    
    local results=$(ldap_search "$templates_dn" 1 "(objectClass=pKICertificateTemplate)" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucun Certificate Template trouvé (AD CS pas configuré ?)" >&2
        return 0
    fi
    
    local count=0
    > "$COLLECTED_CERTTEMPLATES"
    
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local name=$(extract_attribute_value "$line" "name")
            local display_name=$(extract_attribute_value "$line" "displayName")
            local cert_name_flag=$(extract_pki_cert_name_flag "$line")
            local enrollment_flag=$(extract_pki_enrollment_flag "$line")
            local private_key_flag=$(extract_pki_private_key_flag "$line")
            local eku=$(extract_attribute_value "$line" "pKIExtendedKeyUsage")
            local app_policy=$(extract_attribute_value "$line" "msPKI-Certificate-Application-Policy")
            local ra_signature=$(extract_attribute_value "$line" "msPKI-RA-Signature")
            local schema_version=$(extract_attribute_value "$line" "msPKI-Template-Schema-Version")
            local min_key_size=$(extract_attribute_value "$line" "msPKI-Minimal-Key-Size")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            [ -z "$when_created" ] && when_created="-1"
            
            if [ -n "$dn" ] && [ -n "$name" ]; then
                echo "$dn|$name|$display_name|$cert_name_flag|$enrollment_flag|$private_key_flag|$eku|$app_policy|$ra_signature|$schema_version|$min_key_size|$when_created" >> "$COLLECTED_CERTTEMPLATES"
                
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$object_id|CertTemplate|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count Certificate Templates collectés" >&2
}

################################################################################
# collect_enterprise_cas - Collect AD CS Enterprise Certificate Authorities
#
# Queries CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration
# for all pKIEnrollmentService objects.
#
# Attributes collected:
# - distinguishedName, name, displayName, dNSHostName
# - certificateTemplates (list of enabled template names)
# - cACertificate (binary certificate)
# - nTSecurityDescriptor (ACLs)
#
# Results stored in: COLLECTED_AIACAS, COLLECTED_ACES
################################################################################
collect_enterprise_cas() {
    echo "INFO: Collecte des Enterprise CAs..." >&2
    
    local config_dn="CN=Configuration,$DOMAIN_DN"
    local pki_dn="CN=Public Key Services,CN=Services,$config_dn"
    local enrollment_dn="CN=Enrollment Services,$pki_dn"
    
    local attributes="distinguishedName,name,displayName,dNSHostName,certificateTemplates,cACertificate,whenCreated,nTSecurityDescriptor"
    
    local results=$(ldap_search "$enrollment_dn" 1 "(objectClass=pKIEnrollmentService)" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucune Enterprise CA trouvée (AD CS pas configuré ?)" >&2
        return 0
    fi
    
    local count=0
    > "$COLLECTED_ENTERPRISECAS"
    
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local name=$(extract_attribute_value "$line" "name")
            local display_name=$(extract_attribute_value "$line" "displayName")
            local dns_hostname=$(extract_attribute_value "$line" "dNSHostName")
            local cert_templates=$(extract_multivalued_attribute "$line" "certificateTemplates")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            [ -z "$when_created" ] && when_created="-1"
            
            if [ -n "$dn" ] && [ -n "$name" ]; then
                echo "$dn|$name|$display_name|$dns_hostname|$cert_templates|$when_created" >> "$COLLECTED_ENTERPRISECAS"
                
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$object_id|EnterpriseCA|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count Enterprise CAs collectées" >&2
}

################################################################################
# collect_ntauthstores - Collect NTAuth Store objects
#
# NTAuthStore contains trusted root certificates for client authentication
# DN: CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=...
################################################################################
collect_ntauthstores() {
    echo "INFO: Collecte des NTAuth Stores..." >&2
    
    local config_dn="CN=Configuration,$DOMAIN_DN"
    local pki_dn="CN=Public Key Services,CN=Services,$config_dn"
    local ntauth_dn="CN=NTAuthCertificates,$pki_dn"
    
    local attributes="distinguishedName,name,cACertificate,whenCreated,nTSecurityDescriptor"
    
    # NTAuthStore is a single object, not a search
    local results=$(ldap_search "$ntauth_dn" 0 "(objectClass=*)" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: NTAuthStore non trouvé (AD CS pas configuré ?)" >&2
        return 0
    fi
    
    local count=0
    > "$COLLECTED_NTAUTHSTORES"
    
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local name=$(extract_attribute_value "$line" "name")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            [ -z "$when_created" ] && when_created="-1"
            
            # Extract SHA1 thumbprints from certificates
            local cert_thumbprints=$(extract_cert_thumbprints "$line")
            
            if [ -n "$dn" ]; then
                echo "$dn|$name|$cert_thumbprints|$when_created" >> "$COLLECTED_NTAUTHSTORES"
                
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$object_id|NTAuthStore|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count NTAuth Store collecté" >&2
}

################################################################################
# collect_aiacas - Collect AIA CA objects (Authority Information Access)
#
# AIACAs are located in CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration
# They contain certificate chain information
################################################################################
collect_aiacas() {
    echo "INFO: Collecte des AIA CAs..." >&2
    
    local config_dn="CN=Configuration,$DOMAIN_DN"
    local pki_dn="CN=Public Key Services,CN=Services,$config_dn"
    local aia_dn="CN=AIA,$pki_dn"
    
    local attributes="distinguishedName,name,cACertificate,crossCertificatePair,whenCreated,nTSecurityDescriptor"
    
    local results=$(ldap_search "$aia_dn" 1 "(objectClass=certificationAuthority)" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucune AIA CA trouvée (AD CS pas configuré ?)" >&2
        return 0
    fi
    
    local count=0
    > "$COLLECTED_AIACAS"
    
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local name=$(extract_attribute_value "$line" "name")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            [ -z "$when_created" ] && when_created="-1"
            
            # Extract SHA1 thumbprints from certificates
            local cert_thumbprints=$(extract_cert_thumbprints "$line")
            local has_cross_cert="false"
            if [[ "$line" =~ crossCertificatePair ]]; then
                has_cross_cert="true"
            fi
            
            if [ -n "$dn" ] && [ -n "$name" ]; then
                echo "$dn|$name|$cert_thumbprints|$has_cross_cert|$when_created" >> "$COLLECTED_AIACAS"
                
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$object_id|AIACA|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count AIA CAs collectées" >&2
}

################################################################################
# collect_rootcas - Collect Root CA objects
#
# RootCAs are located in CN=Certification Authorities,CN=Public Key Services
# They represent trusted root certification authorities
################################################################################
collect_rootcas() {
    echo "INFO: Collecte des Root CAs..." >&2
    
    local config_dn="CN=Configuration,$DOMAIN_DN"
    local pki_dn="CN=Public Key Services,CN=Services,$config_dn"
    local rootca_dn="CN=Certification Authorities,$pki_dn"
    
    local attributes="distinguishedName,name,cACertificate,whenCreated,nTSecurityDescriptor"
    
    local results=$(ldap_search "$rootca_dn" 1 "(objectClass=certificationAuthority)" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucune Root CA trouvée (AD CS pas configuré ?)" >&2
        return 0
    fi
    
    local count=0
    > "$COLLECTED_ROOTCAS"
    
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local name=$(extract_attribute_value "$line" "name")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            [ -z "$when_created" ] && when_created="-1"
            
            # Extract SHA1 thumbprints from certificates
            local cert_thumbprints=$(extract_cert_thumbprints "$line")
            
            if [ -n "$dn" ] && [ -n "$name" ]; then
                echo "$dn|$name|$cert_thumbprints|$when_created" >> "$COLLECTED_ROOTCAS"
                
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$object_id|RootCA|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count Root CAs collectées" >&2
}

################################################################################
# collect_issuancepolicies - Collect Certificate Issuance Policy objects
#
# Issuance Policies are located in CN=OID,CN=Public Key Services
# They define certificate issuance policies (Low/Medium/High Assurance, etc.)
################################################################################
collect_issuancepolicies() {
    echo "INFO: Collecte des Issuance Policies..." >&2
    
    local config_dn="CN=Configuration,$DOMAIN_DN"
    local pki_dn="CN=Public Key Services,CN=Services,$config_dn"
    local oid_dn="CN=OID,$pki_dn"
    
    local attributes="distinguishedName,name,displayName,msPKI-Cert-Template-OID,whenCreated,nTSecurityDescriptor"
    
    local results=$(ldap_search "$oid_dn" 1 "(objectClass=msPKI-Enterprise-Oid)" "$attributes")
    
    if [ -z "$results" ]; then
        echo "WARN: Aucune Issuance Policy trouvée (AD CS pas configuré ?)" >&2
        return 0
    fi
    
    local count=0
    > "$COLLECTED_ISSUANCEPOLICIES"
    
    while IFS= read -r line; do
        if [ -n "$line" ] && [[ "$line" =~ ^308 ]]; then
            local dn=$(extract_dn_from_response "$line")
            local name=$(extract_attribute_value "$line" "name")
            local display_name=$(extract_attribute_value "$line" "displayName")
            local cert_template_oid=$(extract_attribute_value "$line" "msPKI-Cert-Template-OID")
            local when_created=$(extract_filetime_timestamp "$line" "whenCreated")
            [ -z "$when_created" ] && when_created="-1"
            
            if [ -n "$dn" ]; then
                echo "$dn|$name|$display_name|$cert_template_oid|$when_created" >> "$COLLECTED_ISSUANCEPOLICIES"
                
                local dn_upper=$(echo "$dn" | tr '[:lower:]' '[:upper:]')
                local object_id=$(echo -n "$dn_upper" | md5sum | awk '{print toupper($1)}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/')
                
                local aces=$(extract_aces_from_ldap_response "$line")
                if [ -n "$aces" ]; then
                    while IFS='|' read -r principal_sid right_name is_inherited; do
                        if [ -n "$principal_sid" ] && [ -n "$right_name" ]; then
                            echo "$object_id|IssuancePolicy|$principal_sid|$right_name|$is_inherited" >> "$COLLECTED_ACES"
                        fi
                    done <<< "$aces"
                fi
                
                ((count++))
            fi
        fi
    done <<< "$results"
    
    echo "INFO: $count Issuance Policies collectées" >&2
}
