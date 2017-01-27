#!/usr/bin/python
# TODO: License goes here

import ansible.modules.cloud.amazon.iot_topic_rule as iot_topic_rule
from ansible.modules.cloud.amazon.iot_topic_rule import IoTTopicRule
import mock
from mock import patch
from mock import create_autospec
from mock import ANY
import unittest
import boto
import copy
from botocore.exceptions import BotoCoreError

class TestIoTTopicRule(unittest.TestCase):

    def setUp(self):
        self.module = mock.MagicMock()
        self.module.check_mode = False
        self.module.exit_json = mock.MagicMock()
        self.module.fail_json = mock.MagicMock()
        self.iot_topic_rule = IoTTopicRule(self.module)
        self.iot_topic_rule.iot_client = mock.MagicMock()
        self.iot_topic_rule.module.params = {
                'name': 'some_iot_rule_name',
                'description': 'iot_rule_description',
                'sql': 'select * from some_topic',
                'state': 'present',
                'actions': {'s3': { 'some_s3_key': 'some_s3_value' }},
                'awsIotSqlVersion': '2016-03-23'
                }
        reload(iot_topic_rule)

    def test_boto_module_not_found(self):
        # Setup Mock Import Function
        import __builtin__ as builtins
        real_import = builtins.__import__

        def mock_import(name, *args):
            if name == 'boto': raise ImportError
            return real_import(name, *args)

        with mock.patch('__builtin__.__import__', side_effect=mock_import):
            reload(iot_topic_rule)
            IoTTopicRule(self.module)

            self.module.fail_json.assert_called_with(msg='boto and boto3 are required for this module')

    def test_boto3_module_not_found(self):
        # Setup Mock Import Function
        import __builtin__ as builtins
        real_import = builtins.__import__

        def mock_import(name, *args):
            if name == 'boto3': raise ImportError
            return real_import(name, *args)

        with mock.patch('__builtin__.__import__', side_effect=mock_import):
            reload(iot_topic_rule)
            IoTTopicRule(self.module)

        self.module.fail_json.assert_called_with(msg='boto and boto3 are required for this module')


    @patch.object(iot_topic_rule, 'boto3')
    def test_boto3_client_properly_instantiated(self, mock_boto):
        IoTTopicRule(self.module)
        mock_boto.client.assert_called_once_with('iot')


    def test_define_argument_spec(self):
        result = IoTTopicRule._module_argument_spec()
        self.assertIsInstance(result, dict)

    def test_process_handles_new_rule(self):
        response = { 'rules': [ { 'ruleName': 'iot_rule_we_are_not_looking_for' } ] }
        self.iot_topic_rule.iot_client.list_topic_rules.return_value = response

        self.iot_topic_rule.process()

        assert self.iot_topic_rule.iot_client.list_topic_rules.call_count == 1
        self.iot_topic_rule.iot_client.create_topic_rule.assert_called_once_with(
                ruleName='some_iot_rule_name',
                topicRulePayload=self._get_expected_topic_payload())
        self.iot_topic_rule.module.exit_json.assert_called_once_with(changed=True, name='some_iot_rule_name')

    def test_process_when_state_is_not_specified_handles_new_rule(self):
        del self.iot_topic_rule.module.params['state']
        response = { 'rules': [ { 'ruleName': 'iot_rule_we_are_not_looking_for' } ] }
        self.iot_topic_rule.iot_client.list_topic_rules.return_value = response

        self.iot_topic_rule.process()

        assert self.iot_topic_rule.iot_client.list_topic_rules.call_count == 1
        self.iot_topic_rule.iot_client.create_topic_rule.assert_called_once_with(
                ruleName='some_iot_rule_name',
                topicRulePayload=self._get_expected_topic_payload())
        self.iot_topic_rule.module.exit_json.assert_called_once_with(changed=True, name='some_iot_rule_name')

    def test_process_handles_updating_existing_rule(self):
        response = { 'rules': [ { 'ruleName': 'some_iot_rule_name' } ] }
        self.iot_topic_rule.iot_client.list_topic_rules.return_value = response

        self.iot_topic_rule.process()

        assert self.iot_topic_rule.iot_client.list_topic_rules.call_count == 1
        self.iot_topic_rule.iot_client.replace_topic_rule.assert_called_once_with(
                ruleName='some_iot_rule_name',
                topicRulePayload=self._get_expected_topic_payload())
        self.iot_topic_rule.module.exit_json.assert_called_once_with(changed=True, name='some_iot_rule_name')

    def test_process_handles_updating_existing_rule_when_nothing_has_changed(self):
        list_response = { 'rules': [ { 'ruleName': 'some_iot_rule_name' } ] }
        get_response = \
            {
                'rule':
                    {
                        'ruleName': 'some_iot_rule_name',
                        'description': 'iot_rule_description',
                        'sql': 'select * from some_topic',
                        'actions': [{'s3': { 'some_s3_key': 'some_s3_value' }}],
                        'awsIotSqlVersion': '2016-03-23'
                    }
            }

        self.iot_topic_rule.iot_client.list_topic_rules.return_value = list_response
        self.iot_topic_rule.iot_client.get_topic_rule.return_value = get_response

        self.iot_topic_rule.process()

        assert self.iot_topic_rule.iot_client.list_topic_rules.call_count == 1
        assert self.iot_topic_rule.iot_client.get_topic_rule.call_count == 1
        self.iot_topic_rule.iot_client.replace_topic_rule.assert_not_called()
        self.iot_topic_rule.module.exit_json.assert_called_once_with(changed=False, name='some_iot_rule_name')

    def test_process_when_state_is_not_specified_handles_updating_existing_rule(self):
        del self.iot_topic_rule.module.params['state']
        response = { 'rules': [ { 'ruleName': 'some_iot_rule_name' } ] }
        self.iot_topic_rule.iot_client.list_topic_rules.return_value = response

        self.iot_topic_rule.process()

        assert self.iot_topic_rule.iot_client.list_topic_rules.call_count == 1
        self.iot_topic_rule.iot_client.replace_topic_rule.assert_called_once_with(
                ruleName='some_iot_rule_name',
                topicRulePayload=self._get_expected_topic_payload())
        self.iot_topic_rule.module.exit_json.assert_called_once_with(changed=True, name='some_iot_rule_name')

    def test_process_handles_deleting_existing_rule(self):
        self.iot_topic_rule.module.params['state'] = 'absent'
        response = { 'rules': [ { 'ruleName': 'some_iot_rule_name' } ] }
        self.iot_topic_rule.iot_client.list_topic_rules.return_value = response

        self.iot_topic_rule.process()

        assert self.iot_topic_rule.iot_client.list_topic_rules.call_count == 1
        self.iot_topic_rule.iot_client.delete_topic_rule.assert_called_once_with(ruleName='some_iot_rule_name')
        self.iot_topic_rule.module.exit_json.assert_called_once_with(changed=True, name='some_iot_rule_name')

    def test_process_handles_deleting_non_existing_rule(self):
        self.iot_topic_rule.module.params['state'] = 'absent'
        response = { 'rules': [ { 'ruleName': 'not_the_rule_were_looking_for' } ] }
        self.iot_topic_rule.iot_client.list_topic_rules.return_value = response

        self.iot_topic_rule.process()

        assert self.iot_topic_rule.iot_client.list_topic_rules.call_count == 1
        self.iot_topic_rule.iot_client.delete_topic_rule.assert_not_called()
        self.iot_topic_rule.module.exit_json.assert_called_once_with(changed=False, name='some_iot_rule_name')

    def test_process_handles_elasticsearch_document_type_to_type_transformation(self):
        response = { 'rules': [] }
        self.iot_topic_rule.module.params['actions'] = \
                {
                    'elasticsearch': { 'documentType': 'some_doc_type' }
                }
        self.iot_topic_rule.iot_client.list_topic_rules.return_value = response

        self.iot_topic_rule.process()

        assert self.iot_topic_rule.iot_client.list_topic_rules.call_count == 1
        self.iot_topic_rule.iot_client.create_topic_rule.assert_called_once_with(
                ruleName='some_iot_rule_name',
                topicRulePayload=self._get_expected_topic_payload_for_elasticsearch())
        self.iot_topic_rule.module.exit_json.assert_called_once_with(changed=True, name='some_iot_rule_name')

    def test_process_handles_botocore_exceptions(self):
        self.iot_topic_rule.module.params['state'] = 'absent'
        self.iot_topic_rule.iot_client.list_topic_rules.side_effect = BotoCoreError

        self.iot_topic_rule.process()

        assert self.iot_topic_rule.iot_client.list_topic_rules.call_count == 1
        self.iot_topic_rule.module.fail_json.assert_called_once_with(
          msg='Error when processing topic rules via boto3: An unspecified error occurred')
        self.iot_topic_rule.module.exit_json.assert_called_once_with(changed=False, name='some_iot_rule_name')


    @patch.object(iot_topic_rule, 'AnsibleModule')
    @patch.object(iot_topic_rule, 'IoTTopicRule')
    def test_main(self, mock_IoTTopicRule, mock_AnsibleModule):
        mock_IoTTopicRule_instance      = mock.MagicMock()
        mock_AnsibleModule_instance     = mock.MagicMock()
        mock_IoTTopicRule.return_value  = mock_IoTTopicRule_instance
        mock_AnsibleModule.return_value = mock_AnsibleModule_instance

        iot_topic_rule.main()

        mock_IoTTopicRule.assert_called_once_with(mock_AnsibleModule_instance)
        assert mock_IoTTopicRule_instance.process.call_count == 1


# helper functions

    def _get_expected_topic_payload(self):
        topic_rule_payload = copy.deepcopy(self.iot_topic_rule.module.params)
        topic_rule_payload.pop('name', None)
        topic_rule_payload.pop('state', None)
        return self._wrap_actions_in_list(topic_rule_payload)

    def _get_expected_topic_payload_for_elasticsearch(self):
        topic_rule_payload = self._unwrap_actions_from_list(self._get_expected_topic_payload())
        topic_rule_payload['actions']['elasticsearch']['type'] = topic_rule_payload['actions']['elasticsearch']['documentType']
        topic_rule_payload['actions']['elasticsearch'].pop('documentType', None)
        return self._wrap_actions_in_list(topic_rule_payload)

    def _unwrap_actions_from_list(self, payload):
        payload['actions'] = payload['actions'][0]
        return payload

    def _wrap_actions_in_list(self, payload):
        payload['actions'] = [payload['actions']]
        return payload

if __name__ == '__main__':
    unittest.main()


