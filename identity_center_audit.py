import boto3
import sys
import os
import time
from pydantic import BaseModel


## Lists that will be using pydantic BaseModels.
assignments_for_principals = []
users = []
groups = []
group_members = []
accounts = []

## Data model policies for various lists.  Using pydantic to allow this data to be manipulated and called more easily.

## User and group lists.
class PrincipalListPolicy(BaseModel):
    principal_id: str
    principal_name: str

## List of accounts in Organization
class AccountsListPolicy(BaseModel):
    account_num: str
    account_name: str

## List of account assignments for principals (users / groups), enriched with human-readable data.
class AssignmentsForPrincipalsPolicy(BaseModel):
    requesting_principal_name: str
    requesting_principal_id: str
    requesting_principal_type: str ## ("USER" | "GROUP") 
    ## The effecting principal_type (PrincipalType) and effecting principal_id (PrincipalId) are the return values that describe how the principal has access to the account.
    effecting_principal_type: str ## ("USER" | "GROUP") 
    effecting_principal_id: str
    effecting_principal_name: str
    account_num: str
    permset_name: str
    permset_arn: str
    permset_desc: str



def main(profile_name=None):        
    session = boto3.Session(profile_name=profile_name)
    AWS_REGION = "us-east-1"

    ###############################################################
    ## STS
    ## Get current session information.
    # sts_client = session.client('sts', region_name=AWS_REGION)
    # current_account_number = sts_client.get_caller_identity()['Account']
    # print(current_account_number)

    ###############################################################
    ## ORGANIZATIONS
    ## Get accounts in Organization.
    org_client = session.client('organizations', region_name=AWS_REGION)

    account_list_pages = org_client.get_paginator('list_accounts')
    for page in account_list_pages.paginate():
        for account in page["Accounts"]:
            account_name = account["Name"]
            account_num = account["Id"]
            ## Append the account info into the accounts list.
            accounts.append(AccountsListPolicy(
                account_num=account_num,
                account_name=account_name
            ))
    global account_list
    account_list = [x.account_num for x in accounts]

    ###############################################################
    ## IAM IDENTITY CENTER.
    ## Get some initial housekeeping done in Identity Center.
    global sso_admin_client, identitystore_client, identity_store_id, sso_instance_arn
    sso_admin_client = session.client('sso-admin', region_name=AWS_REGION)
    identitystore_client = session.client('identitystore', region_name=AWS_REGION)
    sso_instance = sso_admin_client.list_instances()
    # print(f"{sso_instance}\n")
    identity_store_id = (sso_instance['Instances'][0]['IdentityStoreId'])
    sso_instance_arn = (sso_instance['Instances'][0]['InstanceArn'])
    # print(f"\nIdentityStoreId: {identity_store_id}")
    # print(f"SsoInstanceArn: {sso_instance_arn}\n")

    ## Get users in Identity Store.
    user_list_pages = identitystore_client.get_paginator('list_users').paginate(IdentityStoreId=identity_store_id)
    user_list_build = user_list_pages.build_full_result()
    user_list = user_list_build['Users']
    for user in user_list:
        principal_name = user['UserName']
        principal_id = user['UserId']
        ## Append the user info into the users list.
        users.append(PrincipalListPolicy(
            principal_id=principal_id,
            principal_name=principal_name
        ))

    ## Get groups in Identity Store.
    group_list_pages = identitystore_client.get_paginator('list_groups').paginate(IdentityStoreId=identity_store_id)
    group_list_build = group_list_pages.build_full_result()
    group_list = group_list_build['Groups']

    for group in group_list:
        principal_name = group['DisplayName']
        principal_id = group['GroupId']
        ## Append the user info into the users list.
        groups.append(PrincipalListPolicy(
            principal_id=principal_id,
            principal_name=principal_name
        ))


    ###############################################################
    ## INITIAL PROMPT.
    print(f"\n\n###############################################################")
    print(f"\nThis is an IAM Identity Center audit script. \n\nTo evaluate the principal or resource, select one of the options from the following...\n")
    choice = input(f"\tType \"1\" for a list of Identity Center USERS. \n\tType \"2\" for a list of Identity Center GROUPS. \n\tType \"3\" for a list of ACCOUNTS in the Organization. \n\n")
    while choice not in ['1', '2', '3']:
        print(f"\nInvalid input. Please re-run script and try again.\n")
        sys.exit(1)
    
    type_selection = int(choice)

    ## User selection (1).
    if type_selection == 1:
        selectUser()

    ## Group selection (2).
    if type_selection == 2:
        selectGroup()

    ## Account selection (3).
    if type_selection == 3:
        selectAccount()
    


def selectUser():
    ## Print a list of users with index numbers.
    print(f"\nThis is a list of users in Identity Store.")

    users_sorted = sorted(users, key=lambda x: x.principal_name)
    for i, user in enumerate(users_sorted):
        print(f"{i}) {user.principal_name} , {user.principal_id}")

    ## Prompt to select a number.
    selection_input_value = input(f"\nSelect a number from the list above to look up the principal's account assignments: ")

    ## Convert the input to an integer.
    try:
        selected_index = int(selection_input_value)
    except:
        print(f"\nInvalid selection. Please choose a number within the valid range.")
        sys.exit(1)

    if 0 <= selected_index < len(users_sorted):
        input_value = "Good"
    else:
        input_value = "Bad"
    if input_value == "Bad":
        print("Invalid selection. Please choose a number within the valid range.")
        sys.exit(1)

    data_at_index = users_sorted[selected_index]

    ## Check if the selected index is within the valid range.
    if 0 <= selected_index < len(users_sorted):
        print(f"\nSelected: {data_at_index}\n")
        requesting_principal_name = data_at_index.principal_name
        requesting_principal_id = data_at_index.principal_id
        requesting_principal_type = "USER"
    else:
        print("Invalid selection. Please choose a number within the valid range.")
        sys.exit(1)

    getAccountAssignmentsForPrincipal(requesting_principal_id, requesting_principal_name, requesting_principal_type)

    print(f"\nThe {requesting_principal_type} {requesting_principal_name} has the following account assignments in Identity Center:\n")

    ## Sort the list by "".
    # assignments_for_principals_sorted = sorted(assignments_for_principals, key=lambda x: x.effecting_principal_name)
    assignments_for_principals_sorted = sorted(assignments_for_principals, key=lambda x: x.account_num)

    for assignment in assignments_for_principals_sorted:
        print(f"\t{assignment.requesting_principal_type} has access to account # {assignment.account_num}, with permission set {assignment.permset_name}, via {assignment.effecting_principal_type} {assignment.effecting_principal_name}.")

    ## Get some simple metrics regarding the accounts principal is assigned to.
    unique_accounts_in_assignments = [x.account_num for x in assignments_for_principals]
    ## Sort the account numbers as strings (preserving leading zeros).
    unique_accounts_in_assignments = sorted(unique_accounts_in_assignments, key=lambda x: (len(x), x))
    ## Remove duplicates while preserving the sorted order.
    unique_accounts_in_assignments = list(dict.fromkeys(unique_accounts_in_assignments))
    ## Count the number of the unique accounts.
    unique_accounts_in_assignments_count = len(unique_accounts_in_assignments)

    ## Evaluate what accounts the principal has access to, and does not have access to.
    print(f"\n\nThe {requesting_principal_type} {requesting_principal_name} has access to {unique_accounts_in_assignments_count} account(s): \n")
    for acct_num in unique_accounts_in_assignments:
        ## Enrich this data with the account_name.
        acct_name = ""
        for a in accounts:
            if acct_num == a.account_num:
                acct_name = a.account_name
        print(f"\t{acct_num} , {acct_name}")

    difference = list(set(account_list) - set(unique_accounts_in_assignments))
    print(f"\n\nThe {requesting_principal_type} {requesting_principal_name} does NOT have access to the following account(s): \n")
    for acct_num in difference:
        ## Enrich this data with the account_name.
        acct_name = ""
        for a in accounts:
            if acct_num == a.account_num:
                acct_name = a.account_name
        print(f"\t{acct_num} , {acct_name}") 

    ## Get list of groups that a user has membership to.
    print(f"\n\nThe {requesting_principal_type} {requesting_principal_name} is member of the following Identity Center group(s): \n")
    group_memberships_for_member_list_pages = identitystore_client.get_paginator('list_group_memberships_for_member').paginate(
        IdentityStoreId=identity_store_id,
        MemberId={'UserId': requesting_principal_id}
    )
    group_memberships_for_member_list_build = group_memberships_for_member_list_pages.build_full_result()
    group_memberships_for_member_list = group_memberships_for_member_list_build['GroupMemberships']
    # group_memberships_for_member_list_json = json.dumps(group_memberships_for_member_list, indent=4)
    # print(group_memberships_for_member_list_json)
    ## The list of groups:
    for membership in group_memberships_for_member_list:
        group_id = membership['GroupId']
        for g in groups:
            if group_id == g.principal_id:
                group_name = g.principal_name
        print(f"\t{group_id} , {group_name}")
    print(f"\n")



def selectGroup():
    ## Print a list of groups with index numbers.
    print(f"\nThis is a list of groups in Identity Store.")

    groups_sorted = sorted(groups, key=lambda x: x.principal_name)
    for i, group in enumerate(groups_sorted):
        print(f"{i}) {group.principal_name} , {group.principal_id}")

    ## Prompt to select a number.
    selection_input_value = input(f"\nSelect a number from the list above to look up the principal's account assignments: ")

    ## Convert the input to an integer.
    selected_index = int(selection_input_value)
    try:
        selected_index = int(selection_input_value)
    except:
        print(f"\nInvalid selection. Please choose a number within the valid range.")
        sys.exit(1)

    if 0 <= selected_index < len(groups_sorted):
        input_value = "Good"
    else:
        input_value = "Bad"
    if input_value == "Bad":
        print("Invalid selection. Please choose a number within the valid range.")
        sys.exit(1)

    data_at_index = groups_sorted[selected_index]

    ## Check if the selected index is within the valid range.
    if 0 <= selected_index < len(groups_sorted):
        print(f"\nSelected: {data_at_index}\n")
        requesting_principal_name = data_at_index.principal_name
        requesting_principal_id = data_at_index.principal_id
        requesting_principal_type = "GROUP"
    else:
        print("Invalid selection. Please choose a number within the valid range.")
        sys.exit(1)

    getAccountAssignmentsForPrincipal(requesting_principal_id, requesting_principal_name, requesting_principal_type)

    print(f"\nThe {requesting_principal_type} {requesting_principal_name} has the following account assignments in Identity Center:\n")

    ## Sort the list by "".
    # assignments_for_principals_sorted = sorted(assignments_for_principals, key=lambda x: x.effecting_principal_name)
    assignments_for_principals_sorted = sorted(assignments_for_principals, key=lambda x: x.account_num)

    for assignment in assignments_for_principals_sorted:
        print(f"\t{assignment.requesting_principal_name} ({assignment.requesting_principal_type}) has access to account # {assignment.account_num}, with permission set {assignment.permset_name}.")

    ## Get some simple metrics regarding the accounts principal is assigned to.
    unique_accounts_in_assignments = [x.account_num for x in assignments_for_principals]
    ## Sort the account numbers as strings (preserving leading zeros).
    unique_accounts_in_assignments = sorted(unique_accounts_in_assignments, key=lambda x: (len(x), x))
    ## Remove duplicates while preserving the sorted order.
    unique_accounts_in_assignments = list(dict.fromkeys(unique_accounts_in_assignments))
    ## Count the number of the unique accounts.
    unique_accounts_in_assignments_count = len(unique_accounts_in_assignments)

    ## Evaluate what accounts the principal has access to, and does not have access to.
    print(f"\n\nThe {requesting_principal_type} {requesting_principal_name} has access to {unique_accounts_in_assignments_count} account(s): \n")
    for acct_num in unique_accounts_in_assignments:
        ## Enrich this data with the account_name.
        acct_name = ""
        for a in accounts:
            if acct_num == a.account_num:
                acct_name = a.account_name
        print(f"\t{acct_num} , {acct_name}")

    difference = list(set(account_list) - set(unique_accounts_in_assignments))
    print(f"\n\nThe {requesting_principal_type} {requesting_principal_name} does NOT have access to the following account(s): \n")
    for acct_num in difference:
        ## Enrich this data with the account_name.
        acct_name = ""
        for a in accounts:
            if acct_num == a.account_num:
                acct_name = a.account_name
        print(f"\t{acct_num} , {acct_name}") 

    ## Get members of the group.
    print(f"\n\nThe {requesting_principal_type} {requesting_principal_name} has the following members (Identity Center users): \n")
    group_memberships = identitystore_client.list_group_memberships(
        IdentityStoreId= identity_store_id,
        GroupId=requesting_principal_id#,
        # MaxResults=123,
        # NextToken='string'
    )
    group_memberships_list = group_memberships['GroupMemberships']
    for membership in group_memberships_list:
        group_member_id = membership['MemberId']['UserId']
        for user in users:
            if group_member_id == user.principal_id:
                group_member_name = user.principal_name
                ## Append the member (user) info into the group_members list.
                group_members.append(PrincipalListPolicy(
                    principal_id=group_member_id,
                    principal_name=group_member_name
                ))
    group_members_sorted = sorted(group_members, key=lambda x: x.principal_name)
    for member in group_members_sorted:
        print(f"\t{member.principal_name}")

    print(f"\n")



def selectAccount():
    ## Print a list of accounts with index numbers.
    print(f"\nThis is a list of accounts in the organization.\n")

    accounts_sorted = sorted(accounts, key=lambda x: x.account_name)
    for i, account in enumerate(accounts_sorted):
        print(f"{i}) {account.account_num} , {account.account_name}")
    
    ## Prompt to select a number.
    selection_input_value = input(f"\nSelect a number from the list above to look up the assignments for this account: \n")

    ## Convert the input to an integer.
    selected_index = int(selection_input_value)
    try:
        selected_index = int(selection_input_value)
    except:
        print(f"\nInvalid selection. Please choose a number within the valid range.")
        sys.exit(1)

    if 0 <= selected_index < len(accounts_sorted):
        input_value = "Good"
    else:
        input_value = "Bad"
    if input_value == "Bad":
        print("Invalid selection. Please choose a number within the valid range.")
        sys.exit(1)

    data_at_index = accounts_sorted[selected_index]

    print(f"\nSelected: {data_at_index}")
    account_num = data_at_index.account_num
    account_name = data_at_index.account_name
    
    # ## Check if the selected index is within the valid range.
    # if 0 <= selected_index < len(accounts_sorted):
    #     print(f"\nSelected: {data_at_index}")
    #     account_num = data_at_index.account_num
    #     account_name = data_at_index.account_name
    # else:
    #     print("Invalid selection. Please choose a number within the valid range.")
    #     sys.exit(1)
    
    print(f"\nThe following permission sets are provisioned to account {account_num} - {account_name}:\n")
    permission_sets_provisioned_to_account_list_pages = sso_admin_client.get_paginator('list_permission_sets_provisioned_to_account').paginate(
        AccountId=account_num,
        InstanceArn=sso_instance_arn
    )
    permission_sets_provisioned_to_account_list_build = permission_sets_provisioned_to_account_list_pages.build_full_result()
    permission_sets_provisioned_to_account_list = permission_sets_provisioned_to_account_list_build['PermissionSets']
    for permission_set_arn in permission_sets_provisioned_to_account_list:
        ## Get the human-readable permission set name of the permission set arn.
        permission_set_details_response = sso_admin_client.describe_permission_set(InstanceArn=sso_instance_arn, PermissionSetArn=permission_set_arn)
        permission_set_details = permission_set_details_response['PermissionSet']
        permission_set_name = permission_set_details['Name']
        permission_set_desc = permission_set_details.get('Description', '')
        print(f"\t{permission_set_name} - {permission_set_desc}")

    print(f"\n\nThe following is a list of users provisioned to account {account_num} - {account_name}:\n")

    print(f"(Please wait... processing full list of assignments. This can take a few minutes.)\n")
    start_time = time.time()
    
    ## In order to do this next step, we need to fetc all the account assignments provisioned for every user/group, then filter based on the account_num.
    ## This is a RECURSING OPERATION, which can take a few secondes to as much as a few minutes, depending on amount of users in Identity Center.
    for user in users:
        requesting_principal_type = "USER"
        requesting_principal_id = user.principal_id
        requesting_principal_name = user.principal_name
        getAccountAssignmentsForPrincipal(requesting_principal_id, requesting_principal_name, requesting_principal_type)
    for assignment in assignments_for_principals:
        if assignment.account_num == account_num:
            print(f"\t{assignment.requesting_principal_type} {assignment.requesting_principal_name} has access to account # {assignment.account_num}, with permission set {assignment.permset_name}, via {assignment.effecting_principal_type} {assignment.effecting_principal_name}.")
    
    ## How long did this take
    print(f"\n\nProcessing full list of assignments took: %s seconds.\n" % (time.time() - start_time))



def getAccountAssignmentsForPrincipal(requesting_principal_id, requesting_principal_name, requesting_principal_type):
    # ## Get list of account assignments for a principal in Identity Store.
    # report_desc = f'List of account assignments for {requesting_principal_type} principal {requesting_principal_id} in Identity Center:'
    # print(f"\n{report_desc}")
    account_assignments_for_principal_list_pages = sso_admin_client.get_paginator('list_account_assignments_for_principal').paginate(
        InstanceArn=sso_instance_arn,
        PrincipalId=requesting_principal_id,
        PrincipalType=requesting_principal_type
    )
    account_assignments_for_principal_list_build = account_assignments_for_principal_list_pages.build_full_result()
    account_assignments_for_principal_list = account_assignments_for_principal_list_build['AccountAssignments']
    for assignment in account_assignments_for_principal_list:
        account_id = assignment['AccountId']
        permission_set_arn = assignment['PermissionSetArn']
        effecting_principal_id = assignment['PrincipalId']
        effecting_principal_type = assignment['PrincipalType']
        effecting_principal_name = None

        ## Get the human-readable username or groupname of principal_id.
        if effecting_principal_type == 'USER':
            for user in users:
                if user.principal_id == effecting_principal_id:
                    effecting_principal_name = user.principal_name
                    break
        if effecting_principal_type == 'GROUP':
            for group in groups:
                if group.principal_id == effecting_principal_id:
                    effecting_principal_name = group.principal_name
                    break
        

        ## Get the human-readable permission set name of the permission set arn.
        permission_set_details_response = sso_admin_client.describe_permission_set(InstanceArn=sso_instance_arn, PermissionSetArn=permission_set_arn)
        permission_set_details = permission_set_details_response['PermissionSet']
        permission_set_name = permission_set_details['Name']
        permission_set_desc = permission_set_details.get('Description', '')

        # print(f"\t Access to account # {account_id}, with permission set {permission_set_name}, via {effecting_principal_type} {effecting_principal_name}.")

        assignments_for_principals.append(AssignmentsForPrincipalsPolicy(
            requesting_principal_id=requesting_principal_id,
            requesting_principal_name=requesting_principal_name,
            requesting_principal_type=requesting_principal_type,
            effecting_principal_type=effecting_principal_type,
            effecting_principal_name=effecting_principal_name,
            effecting_principal_id=effecting_principal_id,
            account_num=account_id,
            permset_name=permission_set_name,
            permset_arn=permission_set_arn,
            permset_desc=permission_set_desc
        ))


    # ## Get list of permission sets in Identity Store.
    # report_desc = 'List of permission sets in Identity Center.'
    # print(f"\n{report_desc}")
    # permission_sets_list_pages = sso_admin_client.get_paginator('list_permission_sets').paginate(InstanceArn=sso_instance_arn)
    # permission_sets_list_build = permission_sets_list_pages.build_full_result()
    # permission_sets_list = permission_sets_list_build['PermissionSets']
    # permission_sets_list_json = json.dumps(permission_sets_list, indent=4)
    # print(f"{permission_sets_list_json}\n")


    # ## Get list of accounts for a provisioned permission set in Identity Store.
    # report_desc = f'List of accounts for permission set {permission_set_arn} in Identity Center.'
    # print(f"\n{report_desc}")
    # accounts_for_provisioned_permission_set_list_pages = sso_admin_client.get_paginator('list_accounts_for_provisioned_permission_set').paginate(
    #     InstanceArn=sso_instance_arn,
    #     PermissionSetArn=permission_set_arn
    # )
    # accounts_for_provisioned_permission_set_list_build = accounts_for_provisioned_permission_set_list_pages.build_full_result()
    # accounts_for_provisioned_permission_set_list = accounts_for_provisioned_permission_set_list_build['AccountIds']
    # accounts_for_provisioned_permission_set_list_json = json.dumps(accounts_for_provisioned_permission_set_list, indent=4)
    # print(f"\n{accounts_for_provisioned_permission_set_list_json}\n")



## The starter: 
## First, check if a profile name is passed as an argument. If not, then check if environment variables are set. 
if __name__ == "__main__":
    aws_profile = None
    
    if len(sys.argv) == 2:
        aws_profile = sys.argv[1]
        try:
            test_session = boto3.Session(profile_name=aws_profile)
            # sts_client_test = test_session.client('sts', region_name='us-east-1')
            # current_account_number = sts_client_test.get_caller_identity()['Account']
        except Exception as e:
            print(f"\nError: {e}")
            print("\nPlease check your AWS credentials and try again.\n")
            sys.exit(1)

    elif aws_profile is None:
        # aws_profile = get_profile_from_env()    
        if 'AWS_ACCESS_KEY_ID' in os.environ and 'AWS_SECRET_ACCESS_KEY' in os.environ:
            try:
                test_client = boto3.client('sts', region_name='us-east-1')
                current_account_number = test_client.get_caller_identity()['Account']
            except Exception as e:
                print(f"\nError: {e}")
                print("\nPlease check your AWS credentials and try again.\n")
                sys.exit(1)
        else:
            print("\nError: No AWS profile name was passed in argument, nor temporary credentials found in environment variables.")
            print("\n\tUse either a valid AWS local profile or set valid temporary credentials into your environment variables.")
            print("\n\tExample usage with a valid AWS local profile:")
            print("\tpython script_name.py <aws_profile>")
            print("\n\tSee:")
            print("\thttps://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html\n")
            sys.exit(1)
    
    ## Initiate task(s), passing the AWS credentials (aws_profile): 
    main(aws_profile)
