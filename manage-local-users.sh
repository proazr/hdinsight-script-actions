#!/usr/bin/env bash
# shellcheck disable=SC2155

#----------------------------------------------------------------------------------------
# Script for creating HDInsight user accounts & groups locally at the OS & cluster level
#----------------------------------------------------------------------------------------

# declare vars
SERVER=$(hostname -s)
LOG_DIR=/var/log/hdinsight-script-actions-logs
readonly SCRIPT_NAME=$(basename "$0")
LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}-${SERVER}-$(date +%Y-%m-%d_%H-%M-%S).log"

# create log directory
if [ ! -e "$LOG_DIR" ] ; then
	mkdir "$LOG_DIR"
fi

# create log file
touch "$LOG_FILE"

# the admin users group..
SUDO_GROUP="hdi-admin-users"

log() {
	TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
  	echo -e "$TIMESTAMP-$*\r\n" | tee -a "$LOG_FILE"
}

doesOSUserExists() {
	getent passwd "$1"
}

doesOSGroupExists() {
	getent group "$1"
}

createSudoersFile() {
	grep $SUDO_GROUP /etc/group &> /dev/null

	if [ $? == 0 ]; then
		log "$SUDO_GROUP group already exists, skipping step"
	else
		log "Creating group $SUDO_GROUP "
		groupadd $SUDO_GROUP

		SudoersFile='hdi-admin-users'
		if [ -f /etc/sudoers.d/"$SudoersFile" ]
		then
			log "Sudoers file already exists, skipping step."
		else
			log "${SUDO_GROUP} ALL = (ALL) ALL" > "/tmp/$SudoersFile"

			chown root:root "/tmp/$SudoersFile"
			chmod 0440 "/tmp/$SudoersFile"

			log 'checking sudoers file to be placed under /etc/sudoers.d/'

			RET=$(/usr/sbin/visudo -c -f "/tmp/$SudoersFile")
			if [ "$RET" == "/tmp/$SudoersFile: parsed OK" ]; then
				log "sudoers file is OK, moving to /etc/sudoers.d/ "
				mv "/tmp/$SudoersFile" "/etc/sudoers.d/$SudoersFile"
			else
				log "sudoers file is NOT OK. This part will have to be completed manually."
			fi
		fi
	fi
}

doesAmbariUserExists() {
	# returns 0 if user exists 
	# returns 1 if user does not exists

	USER_TO_CHECK=$1

	log "Checking if Ambari user '$USER_TO_CHECK' exists"

	# Get list of users in Ambari
	USER_LIST=$(curl -u "$USERID:$PASSWD" -sS -G "http://${ACTIVEAMBARIHOST}:8080/api/v1/users" | grep 'user_name' | cut -d":" -f2 | tr -d '"','',' ')

	for User in $(echo "$USER_LIST" | tr '\r' ' '); do
		echo "-${User}-"
		if [ "$User" == "$USER_TO_CHECK" ]; then
			echo 0
			log "Specified Ambari user '$USER_TO_CHECK' was found"	
			return
		fi
	done

	# the user does not exists
	echo 1
	log "Specified Ambari user '$USER_TO_CHECK' was NOT found - HTTP error occured"	
}

doesAmbariGroupExists() {
	# returns 0 if group exists
	# returns 1 if group does not exists

	GROUP_TO_CHECK=$1

	log "Checking if Ambari group '$GROUP_TO_CHECK' exists"

	# store the whole response with the status at the and
	HTTP_RESPONSE=$(curl -u "$USERID:$PASSWD" --silent --write-out "HTTPSTATUS:%{http_code}" -G "http://${ACTIVEAMBARIHOST}:8080/api/v1/groups")

	# extract the status
	HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

	if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
		# Get list of groups in Ambari
		IFS=$'\n'
		GROUP_LIST=$(curl -u "$USERID:$PASSWD" -sS -G "http://${ACTIVEAMBARIHOST}:8080/api/v1/groups" | grep 'group_name' | cut -d":" -f2 | tr -d '"','',' ')
		unset IFS

		for GROUP in $GROUP_LIST; do
			if [ "$GROUP" == "$GROUP_TO_CHECK" ]; then
				echo 0 
				log "Specified Ambari group '$GROUP_TO_CHECK' found"
				return
			fi
		done
	else
		echo 1
		log "Specified Ambari group '$GROUP_TO_CHECK' was NOT found"
		return
	fi

	# the group does not exists
	echo 1
	log "Specified Ambari group '$GROUP_TO_CHECK' was NOT found - HTTP error occured"
}

doesUserBelongToAmbariGroup() {
	# returns 0 if the user is a member of the specified group
	# returns 1 if the user is not a member of the specified group

	USER_TO_CHECK=$1
	GROUP_TO_CHECK=$2

	# store the whole response with the status at the and
	HTTP_RESPONSE=$(curl -u "$USERID:$PASSWD" --silent --write-out "HTTPSTATUS:%{http_code}" -G "http://${ACTIVEAMBARIHOST}:8080/api/v1/groups/${GROUP_TO_CHECK// /%20}/members")

	# extract the status
	HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

	if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
		# Get members of the group
		IFS=$'\n'
		USER_LIST=$(curl -u "$USERID:$PASSWD" -sS -G "http://${ACTIVEAMBARIHOST}:8080/api/v1/groups/${GROUP_TO_CHECK// /%20}/members" | grep 'user_name' | cut -d":" -f2 | tr -d '"','',' ')
		unset IFS

		for User in $USER_LIST; do
			if [  "$User" == "$USER_TO_CHECK" ];then
				echo 0
				return
			fi
		done	
	else 
		echo 1
		return
	fi

	# the user is not a member of the specified group
	echo 1
}

getActiveAmbariHost() {
	# only one of the 2 headnodes will be active at any given time
	# identify if hn0 or hn1 is the active headnode

	HOST1="hn0-$(hostname |cut -d"-" -f2-)"
	HOST2="hn1-$(hostname |cut -d"-" -f2-)"

	HTTP_RESPONSE=$(curl -i --write-out "HTTPSTATUS:%{http_code}" --output /dev/null --silent "http://${HOST1}:8080")

	# extract the status
	HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

	if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
		echo "$HOST1"
	else
		echo "$HOST2"
	fi
}

assignRoleToClusterUserGroup() {
	log "Assigning CLUSTER.USER Ambari role to clusteruser group"

	HTTP_RESPONSE=$(curl \
		-i -v -s \
		-w "HTTPSTATUS:%{http_code}" \
		-u "$USERID:$PASSWD" \
		-H "X-Requested-By: ambari" \
		-X POST \
		-d '[{"PrivilegeInfo":{"permission_name":"CLUSTER.USER","principal_name":"clusteruser","principal_type":"GROUP"}}]' \
		"http://${ACTIVEAMBARIHOST}:8080/api/v1/clusters/${CLUSTERNAME}/privileges")

	# extract the status
	HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

	if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
		log "Granted clusteruser group to the CLUSTER USER Ambari role"
	else 
		log "Error occured in adding clusteruser group to the CLUSTER USER Ambari role: ${HTTP_RESPONSE}"
	fi
}

assignRoleToClusterAdministratorGroup() {
	log "Assigning CLUSTER.ADMINISTRATOR Ambari role to clusteradministrator group"

	HTTP_RESPONSE=$(curl \
		-i -v -s \
		-w "HTTPSTATUS:%{http_code}" \
		-u "$USERID:$PASSWD" \
		-H "X-Requested-By: ambari" \
		-X POST \
		-d '[{"PrivilegeInfo":{"permission_name":"CLUSTER.ADMINISTRATOR","principal_name":"clusteradministrator","principal_type":"GROUP"}}]' \
		"http://${ACTIVEAMBARIHOST}:8080/api/v1/clusters/${CLUSTERNAME}/privileges")

	# extract the status
	HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

	if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
		log "Granted clusteradministrator group to the CLUSTER ADMINISTRATOR Ambari role"
	else 
		log "Error occured in adding clusteradministrator group to the CLUSTER ADMINISTRATOR Ambari role: ${HTTP_RESPONSE}"
	fi
}

grantHiveViewAccess() {
	AMBARI_GROUP=$1

	log "Granting VIEW.USER privilege to ${"$AMBARI_GROUP"} on Hive view"

	HTTP_RESPONSE=$(curl \
		-i -v -s \
		-w "HTTPSTATUS:%{http_code}" \
		-u "$USERID:$PASSWD" \
		-H "X-Requested-By: ambari" \
		-X POST  \
		-d '[{"PrivilegeInfo":{"permission_name":"VIEW.USER","principal_name":"'"$AMBARI_GROUP"'","principal_type":"GROUP"}}]' \
		"http://${ACTIVEAMBARIHOST}:8080/api/v1/views/HIVE/versions/1.5.0/instances/AUTO_HIVE_INSTANCE/privileges")

	# extract the status
	HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

	if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
		log "Granted ${"$AMBARI_GROUP"} group access to Hive View"
	else 
		log "Error occured in granting ${"$AMBARI_GROUP"} access to Hive View: ${HTTP_RESPONSE}"
	fi
}

grantTezViewAccess() {
	AMBARI_GROUP=$1

	log "Granting VIEW.USER privilege to ${"$AMBARI_GROUP"} on Tez view"

	HTTP_RESPONSE=$(curl \
		-i -v -s \
		-w "HTTPSTATUS:%{http_code}" \
		-u "$USERID:$PASSWD" \
		-H "X-Requested-By: ambari" \
		-X POST  \
		-d '[{"PrivilegeInfo":{"permission_name":"VIEW.USER","principal_name":"'"$AMBARI_GROUP"'","principal_type":"GROUP"}}]' \
		"http://${ACTIVEAMBARIHOST}:8080/api/v1/views/TEZ/versions/1.0.0/instances/TEZ_CLUSTER_INSTANCE/privileges")

	# extract the status
	HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

	if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
		log "Granted ${"$AMBARI_GROUP"} group access to Tez View"
	else 
		log "Error occured in granting ${"$AMBARI_GROUP"} access to Tez View: ${HTTP_RESPONSE}"
	fi
}

grantZeppelinViewAccess() {
	AMBARI_GROUP=$1

	log "Granting VIEW.USER privilege to ${"$AMBARI_GROUP"} on Zeppelin view"

	HTTP_RESPONSE=$(curl \
		-i -v -s \
		-w "HTTPSTATUS:%{http_code}" \
		-u "$USERID:$PASSWD" \
		-H "X-Requested-By: ambari" \
		-X POST  \
		-d '[{"PrivilegeInfo":{"permission_name":"VIEW.USER","principal_name":"'"$AMBARI_GROUP"'","principal_type":"GROUP"}}]' \
		"http://${ACTIVEAMBARIHOST}:8080/api/v1/views/ZEPPELIN/versions/1.0.0/instances/AUTO_ZEPPELIN_INSTANCE/privileges")

	# extract the status
	HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

	if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
		log "Granted ${"$AMBARI_GROUP"} group access to Zeppelin View"
	else 
		log "Error occured in granting ${"$AMBARI_GROUP"} access to Zeppelin View: ${HTTP_RESPONSE}"
	fi
}

AMBARICONFIGS_PY=/var/lib/ambari-server/resources/scripts/configs.py

# get the hdinsight watchdog user credentials - we will use this account to create users and groups in Ambari
USERID=$(sudo python -c "
import hdinsight_common.Constants as c
print c.AMBARI_WATCHDOG_USERNAME
")
log "Retrieved watchdog USERID $USERID"

PASSWD=$(sudo python -c "
import hdinsight_common.ClusterManifestParser as cmp
import hdinsight_common.Constants as c
import base64 as b64
base64pwd = cmp.parse_local_manifest().ambari_users.usersmap[c.AMBARI_WATCHDOG_USERNAME].password
print b64.b64decode(base64pwd)
")
log "Retrieved watchdog PASSWD xxxxxxxxxxxxxxx"

ACTIVEAMBARIHOST=headnodehost
# ACTIVEAMBARIHOST=$(getActiveAmbariHost $USERID $PASSWD)
log "Retrieved active ambari host - $ACTIVEAMBARIHOST"

CLUSTERNAME=$(sudo python -c "
import hdinsight_common.ClusterManifestParser as cmp
print cmp.parse_local_manifest().deployment.cluster_name
")
log "Retrieved cluster name - $CLUSTERNAME"

STORAGE_ACCOUNT_LIST=$(sudo python $AMBARICONFIGS_PY --user="$USERID" --password="$PASSWD" --port=8080 --action=get --host="$ACTIVEAMBARIHOST" --cluster="$CLUSTERNAME" --config-type=core-site | \
	grep 'blob.core' 	| \
	grep keyprovider 	| \
	cut -d":" -f1 		| \
	tr -d '"','' 		| \
	sed "s/fs.azure.account.keyprovider.//g" \
)

log "Retrieved storage account list $STORAGE_ACCOUNT_LIST"

# get the linked 'admin' storage account that contains the user accounts file
for STORAGE_ACCOUNT in $STORAGE_ACCOUNT_LIST; do
	#if grep -q admin "$STORAGE_ACCOUNT"; then 
	if [ "$(echo "$STORAGE_ACCOUNT" | grep admin)" ]; then
		SCRIPT_STORAGE_ACCOUNT=$STORAGE_ACCOUNT
	fi
done

# get the csv file containing the user accounts to create
log "Storage account containing user list: wasbs://scripts@${SCRIPT_STORAGE_ACCOUNT}/"
USER_LIST_FILENAME="$CLUSTERNAME-users.csv"

# delete the file if it already exists
[ -e "/tmp/${USER_LIST_FILENAME}" ] && rm "/tmp/${USER_LIST_FILENAME}"

# check that the file exists
hdfs dfs -test -e "wasbs://scripts@${SCRIPT_STORAGE_ACCOUNT}/${USER_LIST_FILENAME}"
if [ $? != 0 ]; then
	log "Error the user list file does not exist on HDFS at the expected location wasbs://scripts@${SCRIPT_STORAGE_ACCOUNT}/${USER_LIST_FILENAME}"
	exit 1
fi

# create a copy of the file in the tmp directory
log "Copying user list from Azure storage (wasbs://scripts@${SCRIPT_STORAGE_ACCOUNT}/${USER_LIST_FILENAME}) to local file system /tmp"
hdfs dfs -copyToLocal "wasbs://scripts@${SCRIPT_STORAGE_ACCOUNT}/${USER_LIST_FILENAME}" /tmp/

# create sudoers file
createSudoersFile

OLDIFS=$IFS
while IFS=, read -r firstname lastname username uid gid userpassword osusertype ambarigroup comments
do	
	if [ ! "$firstname" == "firstname" ]; then
		log "CSV ENTRY:$firstname|$lastname|$username|$uid|$gid|xxxxxxxxxxxx|$osusertype|$ambarigroup|$comments"
		
		if [ -z "$firstname" ] && [ -z "$lastname" ] && [ -z "$username" ] && [ -z "$uid" ] && [ -z "$gid" ] && [ -z "$userpassword" ] && [ -z "$osusertype" ] && [ -z "$ambarigroup" ]; then
			log "The user list CSV file does not contain the expected columns or a field is empty."
		else
			if [ "$(doesOSUserExists "$username")" ] || [ "$(doesOSGroupExists "$username")" ]; then
				log "Skipping user/group creation - $username already exists at the operating system level"
			else
				log "Creating a new OS user: $username with uid $uid and gid $gid"
				log "User $username does NOT exist, creating user with the specified password "
				
				useradd -m -u "$uid" -U -s /bin/bash "$username"
				if [ $? != 0 ]; then 
					log "Error unable to add a new user with the username: $username"
					exit 1
				fi
				
				echo -e "$userpassword\n$userpassword" | passwd "$username"
				if [ $? != 0 ]; then 
					log "Error changing the password for the user $username"
					exit 1
				fi

				log "Added user $username"
				
				if [ "$osusertype" == "admin" ]; then
					if groups "$username" | grep &>/dev/null "\b$SUDO_GROUP\b"; then
						log "$username is already a member of the sudo group $SUDO_GROUP, nothing to do."
					else
						log "Adding ${username} to the sudo group ${SUDO_GROUP}"
						usermod -a -G "$SUDO_GROUP" "$username"
						if [ $? != 0 ]; then
							log "Error adding the user $username to the sudo group $SUDO_GROUP"
							exit 1
						fi
					fi
				fi
			fi
			
			# only run these commands once on one of the head nodes
			if [[ "$(hostname -s)" == hn0* ]]; then	
				# create Ambari user if it doesn't already exists
				if [ "$(doesAmbariUserExists "$username")" == 0 ]; then
					log "Error user ${username} already exists in Ambari"
				else
					log "Creating ambari user ${username}"
					
					HTTP_RESPONSE=$(curl \
						-i -v -s \
						-w "HTTPSTATUS:%{http_code}" \
						-u "$USERID:$PASSWD" \
						-H "X-Requested-By: ambari" \
						-X POST \
						-d '{"Users/user_name":"'"${username}"'","Users/password":"'"${userpassword}"'","Users/active":"true","Users/admin":"false"}' \
						"http://${ACTIVEAMBARIHOST}:8080/api/v1/users")
					
					# extract the status
					HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

					if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
						log "Added user ${username} to Ambari"
					else 
						log "Error occured in adding user ${username}: ${HTTP_RESPONSE}"
					fi
				fi
				
				# create ambari group if it doesn't already exists
				if [ "$(doesAmbariGroupExists "$ambarigroup")" == 0 ]; then
					log "Error group ${ambarigroup} already exists in Ambari"
				else
					log "Creating ambari group ${ambarigroup}"

					#-o /dev/null 
					HTTP_RESPONSE=$(curl \
						-i -v -s \
						-w "HTTPSTATUS:%{http_code}" \
						-u "$USERID:$PASSWD" \
						-H "X-Requested-By: ambari" \
						-X POST \
						-d '{"Groups/group_name":"'"${ambarigroup}"'"}' \
						"http://${ACTIVEAMBARIHOST}:8080/api/v1/groups")

					# extract the status
					HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

					if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
						log "Added group ${ambarigroup} to Ambari"
					else 
						log "Error occured in adding group ${ambarigroup} to Ambari: ${HTTP_RESPONSE}"
					fi
				fi

				# add the user to the ambari group if s/he is not already a member of the group
				if [ "$(doesUserBelongToAmbariGroup "$username" "$ambarigroup")" == 0 ]; then
					log "Error user ${username} is already a member of the group ${ambarigroup} in Ambari"
				else
					log "Adding ${username} to the group ${ambarigroup} in Ambari"

					HTTP_RESPONSE=$(curl \
						-i -v -s \
						-w "HTTPSTATUS:%{http_code}" \
						-u "$USERID:$PASSWD" \
						-H "X-Requested-By: ambari" \
						-X POST \
						-d '[{"MemberInfo/user_name":"'"${username}"'", "MemberInfo/group_name":"'"${ambarigroup}"'"}]' \
						"http://${ACTIVEAMBARIHOST}:8080/api/v1/groups/${ambarigroup// /%20}/members")

					# extract the status
					HTTP_STATUS=$(echo "$HTTP_RESPONSE" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

					if [[ "$HTTP_STATUS" -ge 200 && "$HTTP_STATUS" -le 299 ]]; then
						log "Added ambari user ${username} to Ambari group ${ambarigroup}"
					else 
						log "Error occured in adding user ${username} to group ${ambarigroup} to Ambari: ${HTTP_RESPONSE}"
					fi
				fi
			fi 
		fi	
	else 
		log "Skipping header row"
	fi
done < "/tmp/${USER_LIST_FILENAME}"
IFS=$OLDIFS

# only run these commands once on one of the head nodes
if [[ "$(hostname -s)" == hn0* ]]; then	

	# Assign roles to ambari groups
	assignRoleToClusterUserGroup
	assignRoleToClusterAdministratorGroup

	# These aren't needed since assigning roles also grant access (VIEW.USER) to available views
	# Grant access to Hive View
	# grantHiveViewAccess "clusteruser"
	# grantHiveViewAccess "clusteradministrator"

	# Grant access to Tez View
	# grantTezViewAccess "clusteruser"
	# grantTezViewAccess "clusteradministrator"

	# Grant access to Zeppelin View
	# grantZeppelinViewAccess "clusteruser"
	# grantZeppelinViewAccess "clusteradministrator"
fi

# Delete the local file
log "Removing user-list csv locally"
[ -e "/tmp/${USER_LIST_FILENAME}" ] && rm "/tmp/${USER_LIST_FILENAME}"

# Delete the blob on one of the head nodes
if [[ "$(hostname -s)" == hn0* ]]; then	
	log "Removing user-list csv from azure storage"
	hdfs dfs -rm "wasbs://scripts@${SCRIPT_STORAGE_ACCOUNT}/${USER_LIST_FILENAME}"
fi

# copy the log file to the linked storage
log "Copying log file from ${LOG_FILE} to (wasbs://logs@${SCRIPT_STORAGE_ACCOUNT})"
hdfs dfs -copyFromLocal -f "$LOG_FILE" "wasbs://logs@${SCRIPT_STORAGE_ACCOUNT}/$(basename "$LOG_FILE")"

exit 0