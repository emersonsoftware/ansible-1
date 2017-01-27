#!/usr/bin/python

# IoT Topic Rule Ansible Modules
#
# Modules in this project allow management of the AWS IoT service.
#
# Authors:
#  - Michael Lazar <7tumbles@gmail.com>
#
# iot_topic_rule
#    Manage creation, update, and removal of AWS IoT Topic Rules
#

## TODO: Add an appropriate license statement

DOCUMENTATION='''
module: iot_topic_rule
description: An Ansible module to create, update, or remove AWS IoT Topic Rule
version: "1.0"
options:
    name:
        description: The rule name of the IoT Topic Rule
        type: string
        required: True
    sql:
        description: The SQL statement used to query the topic
        type: string
        required: True
    description:
        description: The description of the rule
        type: string
        required: False
    actions:
        description: The actions associated with the rule
        type: dict
        required: True
        options:
            s3:
                description: Action section for s3 configuration
                type: dict
                required: False
                options: 
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    bucketName:
                        description: The Amazon S3 bucket
                        type: string
                        required: True
                    key:
                        description: The object key
                        type: string
                        required: True
                    cannedAcl:
                        description: The Amazon S3 canned ACL that controls access to the object identified by the object key
                        type: string
                        required: False
            lambda:
                description: Action section for Lambda invocation
                type: dict
                required: False
                options: 
                    functionArn:
                        description: The ARN of the Lambda function
                        type: string
                        required: True
            kinesis:
                description: Action section for Kinesis stream
                type: dict
                required: False
                options: 
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    streamName:
                        description: The name of the Amazon Kinesis stream
                        type: string
                        required: True
                    partitionKey:
                        description: The partition key
                        type: string
                        required: False
            firehose:
                description: Action section for Kinesis Firehose stream
                type: dict
                required: False
                options: 
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    deliveryStreamName:
                        description: The name of the delivery stream
                        type: string
                        required: True
                    separator:
                        description: A character separator that will be used to separate records written to the Firehose stream
                        type: string
                        choices: ['n', 't', 'rn', ',']
                        required: False
            dynamoDB:
                description: Action section for DynamoDB
                type: dict
                required: False
                options: 
                    tableName:
                        description: The name of the DynamoDB table
                        type: string
                        required: True
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    operation:
                        description: The type of operation to be performed.
                                     This follows the substitution template, so it can be ${operation},
                                     but the substitution must result in one of the following: INSERT , UPDATE , or DELETE
                        choices: ['INSERT', 'UPDATE', 'DELETE']
                        type: string
                        required: True
                    hashKeyField:
                        description: The hash key name
                        type: string
                        required: True
                    hashKeyValue:
                        description: The hash key value
                        type: string
                        required: True
                    hashKeyType:
                        description: The hash key type
                        choices: ['STRING', 'NUMBER']
                        type: string
                        required: False
                    rangeKeyField:
                        description: The range key name
                        type: string
                        required: False
                    rangeKeyValue:
                        description: The range key value
                        type: string
                        required: False
                    rangeKeyType:
                        description: The range key type
                        choices: ['STRING', 'NUMBER']
                        type: string
                        required: False
                    payloadField:
                        description: The action payload. This name can be customized
                        type: string
                        required: False
            dynamoDBv2:
                description: This is a new version of the DynamoDB action.
                             It allows you to write each attribute in an MQTT message payload into a separate DynamoDB column.
                type: dict
                required: False
                options: 
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    putItem:
                        description: Specifies the DynamoDB table to which the message data will be written
                        type: dict
                        required: True
                        options:
                            tableName:
                                description: The table where the message data will be written
                                type: string
                                required: True
            sns:
                description: Action section for publishing to an Amazon SNS topic
                type: dict
                required: False
                options:
                    targetArn:
                        description: The ARN of the SNS topic
                        type: string
                        required: True
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    messageFormat:
                        description: The message format of the message to publish
                        type: string
                        choices: ['JSON', 'RAW']
                        required: False
            sqs:
                description: Action section for publishing to an Amazon SQS Queue
                type: dict
                required: False
                options:
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    queueUrl:
                        description: The URL of the Amazon SQS queue
                        type: string
                        required: True
                    useBase64:
                        description: Specifies whether to use Base64 encoding
                        type: bool
                        required: False
            republish:
                description: Action section for publishing to another MQTT topic
                type: dict
                required: False
                options:
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    topic:
                        description: The name of the MQTT topic
                        type: string
                        required: True
            elasticsearch:
                description: Action section for writing data to an Amazon Elasticsearch Service domain
                type: dict
                required: False
                options:
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    endpoint:
                        description: The endpoint of your Elasticsearch domain
                        type: string
                        required: True
                    index:
                        description: The Elasticsearch index where you want to store your data
                        type: string
                        required: True
                    documentType:
                        description: The type of document you are storing
                        type: string
                        required: True
                    id:
                        description: The unique identifier for the document you are storing
                        type: string
                        required: True
            cloudwatchAlarm:
                description: Change the state of a CloudWatch alarm
                type: dict
                required: False
                options:
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    alarmName:
                        description: The CloudWatch alarm change
                        type: string
                        required: True
                    stateReason:
                        description: The reason for the alarm change
                        type: string
                        required: True
                    stateValue:
                        description: The value of the alarm state
                        type: string
                        required: True
                        choices: ['OK', 'ALARM', 'INSUFFICIENT_DATA']
            cloudwatchMetric:
                description: Action section for capturing a CloudWatch metric
                type: dict
                required: False
                options:
                    roleArn:
                        description: The ARN of the IAM role that grants access
                        type: string
                        required: True
                    metricNamespace:
                        description: The CloudWatch metric namespace name
                        type: string
                        required: True
                    metricName:
                        description: The CloudWatch metric name
                        type: string
                        required: True
                    metricValue:
                        description: The CloudWatch metric value
                        type: string
                        required: True
                    metricUnit:
                        description: The metric unit supported by CloudWatch
                        type: string
                        required: True
                        choices: [
                                    'Seconds', 'Microseconds', 'Milliseconds', 'Bytes', 'Kilobytes',
                                    'Megabytes', 'Gigabytes', 'Terabytes', 'Bits', 'Kilobits', 'Megabits',
                                    'Gigabits', 'Terabits', 'Percent', 'Count', 'Bytes/Second', 'Kilobytes/Second',
                                    'Megabytes/Second', 'Gigabytes/Second', 'Terabytes/Second', 'Bits/Second',
                                    'Kilobits/Second', 'Megabits/Second', 'Gigabits/Second', 'Terabits/Second',
                                    'Count/Second', 'None'
                                 ]
                    metricTimestamp:
                        description: An optional Unix timestamp
                        type: string
                        required: False
    state:
        description: Should this rule exist or not
        choices: ['present', 'absent']
        default: 'present'
        required: False
requirements:
    - python = 2.7
    - boto
    - boto3
notes:
    - This module requires that you have boto and boto3 installed and that your
      credentials are created or stored in a way that is compatible (see
      U(https://boto3.readthedocs.io/en/latest/guide/quickstart.html#configuration)).
'''

EXAMPLES = '''
---
- hosts: localhost
  gather_facts: False
  tasks:
  - name: Make an IoT Topic Rule
    iot_topic_rule:
      name: "iot_rule_name"
      description: "Configure AWS IoT rules"
      sql: "SELECT * FROM 'some_topic/+'"
      state: "present"
      actions:
        s3:
          roleArn: some_role_arn
          bucketName: some_bucket
          key: some_key
        firehose:
          roleArn: some_role_arn
          deliveryStreamName: some_stream_name
'''

RETURN = '''
{
    "name": "iot_rule_name"
    "invocation": {
        "module_name": "iot_topic_rule"
        "module_args": {
            "name": "iot_rule_name",
            "description": "Configure AWS IoT rules",
            "ruleDisabled": false,
            "sql": "SELECT * FROM 'some_topic/+'",
            "awsIotSqlVersion": "2016-03-23",
            "actions": {
                "s3": {
                    "bucketName": "some_bucket",
                    "key": "some_key",
                    "roleArn": "some_role_arn"
                }
                "firehose": {
                    "deliveryStreamName": "some_stream_name",
                    "roleArn": "some_role_arn"
                }
            },
            "state": "present"
        },
    },
    "changed": false,
}
'''

__version__ = '${version}'

import copy

try:
    import boto3
    import boto
    from botocore.exceptions import BotoCoreError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

class IoTTopicRule:
    def __init__(self, module):
        self.module = module
        if (not HAS_BOTO3):
          self.module.fail_json(msg="boto and boto3 are required for this module")

        self.iot_client = boto3.client('iot')

    @staticmethod
    def _module_argument_spec():
       return {
                'name': { 'required': True },
                'sql': { 'required': True },
                'description': { 'required': False },
                'actions':
                    {
                        'required': True,
                        'type': 'dict',
                        'lambda':
                            { 
                                'type': 'dict', 
                                'functionArn': { 'required': True }
                            },
                        's3': 
                            {
                                'type': 'dict',
                                'roleArn': { 'required': True },
                                'bucketName': { 'required': True },
                                'key': { 'required': True },
                                'cannedAcl': { 'required': False },
                            },
                        'kinesis': 
                            {
                                'type': 'dict',
                                'roleArn': { 'required': True },
                                'streamName': { 'required': True },
                                'partitionKey': { 'required': False },
                            },
                        'firehose':
                            {
                                'type': 'dict',
                                'roleArn': { 'required': True },
                                'deliveryStreamName': { 'required': True },
                                'separator': { 'required': False, 'type': 'string', 'choices': ['n', 't', 'rn', ','] },
                            },
                        'dynamoDB': 
                            {
                                'type': 'dict',
                                'tableName': { 'required': True },
                                'roleArn': { 'required': True },
                                'operation': { 'required': True, 'choices': ['INSERT', 'UPDATE', 'DELETE'] },
                                'hashKeyField': { 'required': True },
                                'hashKeyValue': { 'required': True },
                                'hashKeyType': { 'required': False, 'choices': ['STRING', 'NUMBER']},
                                'rangeKeyField': { 'required': False },
                                'rangeKeyValue': { 'required': False },
                                'rangeKeyType': { 'required': False, 'choices': ['STRING', 'NUMBER']},
                                'payloadField': { 'required': False },
                            },
                        'dynamoDBv2':
                            {
                                'type': 'dict',
                                'roleArn': { 'required': True },
                                'putItem':
                                    {
                                        'type': 'dict',
                                        'required': True,
                                        'tableName': { 'required': True }
                                    },
                            },
                        'sns': 
                            {
                                'type': 'dict',
                                'targetArn': { 'required': True },
                                'roleArn': { 'required': True },
                                'messageFormat': { 'required': False, 'choices': ['JSON', 'RAW'] },
                            },
                        'sqs': 
                            {
                                'type': 'dict',
                                'roleArn': { 'required': True },
                                'queueUrl': { 'required': False },
                                'useBase64': { 'type': 'bool', 'required': False, 'default': False },
                            },
                        'republish': 
                            {
                                'type': 'dict',
                                'roleArn': { 'required': True },
                                'topic': { 'required': False },
                            },
                        'elasticsearch': 
                            {
                                'type': 'dict',
                                'roleArn': { 'required': True },
                                'endpoint': { 'required': True },
                                'index': { 'required': True },
                                'documentType': { 'required': True },
                                'id': { 'required': True },
                            },
                        'cloudwatchAlarm':
                            {
                                'type': 'dict',
                                'roleArn': { 'required': True },
                                'alarmName': { 'required': True },
                                'stateReason': { 'required': True },
                                'stateValue': { 'required': True, 'choices': ['OK', 'ALARM', 'INSUFFICIENT_DATA'] },
                            },
                        'cloudwatchMetric':
                            {
                                'type': 'dict',
                                'roleArn': { 'required': True },
                                'metricNamespace': { 'required': True },
                                'metricName': { 'required': True },
                                'metricValue': { 'required': True },
                                'metricTimestamp': { 'required': False },
                                'metricUnit':
                                    {
                                        'required': True,
                                        'choices':
                                            [
                                                'Seconds', 'Microseconds', 'Milliseconds', 'Bytes', 'Kilobytes',
                                                'Megabytes', 'Gigabytes', 'Terabytes', 'Bits', 'Kilobits', 'Megabits',
                                                'Gigabits', 'Terabits', 'Percent', 'Count', 'Bytes/Second', 'Kilobytes/Second',
                                                'Megabytes/Second', 'Gigabytes/Second', 'Terabytes/Second', 'Bits/Second',
                                                'Kilobits/Second', 'Megabits/Second', 'Gigabits/Second', 'Terabits/Second',
                                                'Count/Second', 'None'
                                            ]
                                    },
                            },
                    },


                'state': { 'default': 'present', 'choices': ['present', 'absent'] },
                'ruleDisabled': { 'required': False, 'type': 'bool', 'default': False },
                'awsIotSqlVersion': { 'required': False, 'default': '2016-03-23', 'choices': ['2015-10-08','2016-03-23','beta'] }
              }

    def process(self):
        changed = False
        rule_name, params = self._transform_params(self.module.params)
        try:
            if params.pop('state', 'present') == 'absent':
                changed = self._delete_topic_rule(rule_name)
            elif self._rule_exists(rule_name):
                changed = self._replace_topic_rule(rule_name, params)
            else:
                changed = self._create_topic_rule(rule_name, params)
        except BotoCoreError as e:
            self.module.fail_json(msg="Error when processing topic rules via boto3: {}".format(e))

        self.module.exit_json(changed=changed, name=rule_name)

    def _create_topic_rule(self, rule_name, payload):
        payload['actions'] = [payload['actions']]
        self.iot_client.create_topic_rule(ruleName=rule_name, topicRulePayload=payload)
        return True

    def _replace_topic_rule(self, rule_name, payload):
        payload['actions'] = [payload['actions']]
        if self._has_rule_not_changed(rule_name, payload):
            return False
        self.iot_client.replace_topic_rule(ruleName=rule_name, topicRulePayload=payload)
        return True

    def _delete_topic_rule(self, rule_name):
        if self._rule_exists(rule_name):
            self.iot_client.delete_topic_rule(ruleName=rule_name)
            return True
        return False

    def _rule_exists(self, rule_name):
        for rule in self._list_topic_rules():
            if rule_name == rule['ruleName']:
                return True
        return False

    def _list_topic_rules(self):
        return self.iot_client.list_topic_rules()['rules']

    def _transform_params(self, params):
        new_params = copy.deepcopy(params)
        new_params.pop('name', None)
        if 'elasticsearch' in new_params['actions']:
            new_params['actions']['elasticsearch']['type'] = new_params['actions']['elasticsearch']['documentType']
            new_params['actions']['elasticsearch'].pop('documentType', None)

        return params['name'], new_params

    def _has_rule_not_changed(self, rule_name, submitted_rule):
        existing_rule = self.iot_client.get_topic_rule(ruleName=rule_name)['rule']
        del existing_rule['ruleName']
        return existing_rule == submitted_rule

def main():
    """
    Instantiates the module and calls process_request.
    :return: none
    """
    module = AnsibleModule(
        argument_spec=IoTTopicRule._module_argument_spec(),
        supports_check_mode=False
    )

    iot_topic_rule = IoTTopicRule(module)
    iot_topic_rule.process()

from ansible.module_utils.basic import *  # pylint: disable=W0614
if __name__ == '__main__':
    main()
 
