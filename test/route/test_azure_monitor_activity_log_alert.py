import os
from re import L
from unittest import TestCase
from json import loads, dumps
from jsonpath_ng import parse


class TestMonitorActivityAlertRules(TestCase):
    def __init__(self):
        fp = open(os.getcwd() + "/test/data/test_azure_monitor_alert.json", "r")
        # fp = open(
        #     "C:/Users/LENOVO/Downloads/docs/matos/matosphere/matosphere/test/data/test_azure_monitor_alert.json", "r")
        content = fp.read()
        fp.close()
        self.resources = loads(content)
        # print(self.resources)

    # Use Case : 5.2.1 Ensure that Activity Log Alert exists for Create Policy Assignment
    def test_create_policy_assignment(self):
        """check if create policy assignment alert is created or not
        """
        test_case = 'Microsoft.Authorization/policyAssignments/write'
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Create Policy Assignment")

    # Use Case : 5.2.2 Ensure that Activity Log Alert exists for Delete Policy Assignment
    def test_delete_policy_assignment(self):
        """check if delete policy assignment alert is created or not
        """
        test_case = "Microsoft.Authorization/policyAssignments/delete"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Delete Policy Assignment")

    # Use Case : 5.2.3 Ensure that Activity Log Alert exists for Create or Update Network Security Group
    def test_create_update_network_security_group(self):
        """check if Create or Update Network Security Group alert is created or not
        """
        test_case = "Microsoft.Network/networkSecurityGroups/write"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Create or Update Network Security Group")

    # Use Case : 5.2.4 Ensure that Activity Log Alert exists for Delete Network Security Group
    def test_delete_network_security_group(self):
        """check if Delete Network Security Group alert is created or not
        """
        test_case = "Microsoft.Network/networkSecurityGroups/delete"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Delete Network Security Group")

    # Use Case : 5.2.7 Ensure that Activity Log Alert exists for Create or Update Security Solution
    def test_create_update_security_solution(self):
        """
        check if Create or Update Security Solution alert is created or not
        """
        test_case = "Microsoft.Security/securitySolutions/write"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Create or Update Security solutions")

    # Use Case : 5.2.8 Ensure that Activity Log Alert exists for Delete Security Solution
    def test_delete_security_solution(self):
        """
        check if Delete Security Solution alert is created or not
        """
        test_case = "Microsoft.Security/securitySolutions/delete"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Delete Security Solution")

    # Use Case : Ensure that an activity log alert is created for "Create or Update Load Balancer" events.
    def test_create_update_load_balancer(self):
        """check if Create or Update Load Balancer alert is created or not
        """
        test_case = "Microsoft.Network/loadBalancers/write"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Create or Update Load Balancer")

    # Use Case : Ensure that an activity log alert is created for "Create/Update Azure SQL Database" events.
    def test_create_update_azure_sql_database(self):
        """check if Create/Update Azure SQL Database alert is created or not
        """
        test_case = "Microsoft.Sql/servers/databases/write"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Create/Update Azure SQL Database")

    # Use Case : Ensure there is an activity log alert created for the "Create/Update Storage Account" events.
    def test_create_update_storage_account(self):
        """check if Create/Update Storage Account alert is created or not
        """
        test_case = "Microsoft.Storage/storageAccounts/write"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Create/Update Storage Account")

    # Use Case : Ensure that an activity log alert is created for "Create or Update Virtual Machine (Microsoft.Compute/virtualMachines)" events.
    def test_create_update_virtual_machine(self):
        """check if Create or Update Virtual Machine alert is created or not
        """
        test_case = "Microsoft.Compute/virtualMachines/write"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Create or Update Virtual Machine (Microsoft.Compute/virtualMachines)")

    # Use Case : Ensure that an activity log alert is created for the "Deallocate Virtual Machine (Microsoft.Compute/virtualMachines)" events.
    def test_deallocate_virtual_machine(self):
        """check if deallocate Virtual Machine alert is created or not
        """
        test_case = "Microsoft.Compute/virtualMachines/deallocate/action"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Deallocate Virtual Machine (Microsoft.Compute/virtualMachines)")

    # Use Case : Ensure that an activity log alert is created for "Delete Azure SQL Database (Microsoft.Sql/servers/databases)" events.
    def test_delete_azure_sql_databases(self):
        """check if delete azure sql databases alert is created or not
        """
        test_case = "Microsoft.Sql/servers/databases/delete"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Delete Azure SQL Database (Microsoft.Sql/servers/databases)")

    # Use Case : Ensure there is an activity log alert created for the "Delete Key Vault" events.
    def test_delete_key_vault(self):
        """check if delete azure Delete Key Vault alert is created or not
        """
        test_case = "Microsoft.KeyVault/vaults/delete"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Delete Key Vault")

    # Use Case : Ensure there is an Azure activity log alert created for "Delete Load Balancer" events.
    def test_delete_load_balancer(self):
        """check if Delete Load Balancer alert is created or not
        """
        test_case = "Microsoft.Network/loadBalancers/delete"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Delete Load Balancer")

    # Use Case : Ensure that an activity log alert exists for "Delete Storage Account" events.
    def test_delete_storage_account(self):
        """check if Delete Storage Account alert is created or not
        """
        test_case = "Microsoft.Storage/storageAccounts/delete"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Delete Storage Account")

    # Use Case : Ensure that an activity log alert exists for "Delete Virtual Machine" events
    def test_delete_virtual_machine(self):
        """check if Delete virtual machine alert is created or not
        """
        test_case = "Microsoft.Compute/virtualMachines/delete"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Delete Virtual Machine")

    # Use Case : Ensure that an activity log alert exists for "Power Off Virtual Machine" events.
    def test_power_off_virtual_machine(self):
        """check if power off virtual machine alert is created or not
        """
        test_case = "Microsoft.Compute/virtualMachines/powerOff/action"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Power Off Virtual Machine")

    # Use Case : Ensure that an activity log alert is created for "Rename Azure SQL Database" events.
    def test_rename_azure_sql_database(self):
        """check if Rename Azure SQL Database alert is created or not
        """
        test_case = "Microsoft.Sql/servers/databases/move/action"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Rename Azure SQL Database")

    # Use Case : Ensure that an activity log alert is created for "Update Key Vault (Microsoft.KeyVault/vaults)" events.
    def test_update_key_vault(self):
        """check if Update Key Vault alert is created or not
        """
        test_case = "Microsoft.KeyVault/vaults/write"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Update Key Vault (Microsoft.KeyVault/vaults)")

    # Use Case : Ensure that an activity log alert is created for the "Update Security Policy" events.

    def test_update_security_policy(self):
        """check if Update Security Policy alert is created or not
        """
        test_case = "Microsoft.Security/policies/write"
        count = 0
        for resource in self.resources['log_monitor']:
            test = [i['condition']['all_of'] for i in resource['self']
                    if i['condition']['all_of'][-1]['equals'] == test_case]
            count += len(test)
        flag = count == len(self.resources.get('log_monitor', []))
        return self.assertEqual(True, flag, msg="One of the Resource Group log is not no having Activity Log Alert for Update Security Policy")

    # # Use Case : Ensure that an activity log alert is created for "Create/Update MySQL Database" events.
    # def test_create_update_MYSQL_database(self):
    #     """check if UCreate/Update MySQL Database alert is created or not
    #     """
    #     test_case =
