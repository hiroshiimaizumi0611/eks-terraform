import boto3
import os

elbv2 = boto3.client('elbv2')

def lambda_handler(event, context):
    listener_arn = os.environ['LISTENER_ARN']
    s3_host = os.environ['SORRYPAGE_HOST']  # 例: estimate-app-sorrypage.s3-website-ap-northeast-1.amazonaws.com
    rule_priority = int(os.environ.get('RULE_PRIORITY', '0'))

    action = event.get('action', 'on')  # "on" or "off"

    if action == 'on':
        # すでに同じルールがある場合は先に削除
        rules = elbv2.describe_rules(ListenerArn=listener_arn)['Rules']
        for rule in rules:
            for action_block in rule['Actions']:
                if (action_block['Type'] == 'redirect'
                        and action_block['RedirectConfig'].get('Host') == s3_host):
                    elbv2.delete_rule(RuleArn=rule['RuleArn'])

        # メンテ用リダイレクトルール追加
        resp = elbv2.create_rule(
            ListenerArn=listener_arn,
            Conditions=[{
                'Field': 'host-header',
                'Values': [os.environ['HOST_HEADER']]
            }],
            Priority=rule_priority,
            Actions=[{
                'Type': 'redirect',
                'RedirectConfig': {
                    'Protocol': 'HTTPS',
                    'Host': s3_host,
                    'Port': '443',
                    'Path': '/index.html',
                    'StatusCode': 'HTTP_302'
                }
            }]
        )
        return {"result": "Maintenance mode ON", "response": resp}

    else:
        # メンテ用ルールを削除
        rules = elbv2.describe_rules(ListenerArn=listener_arn)['Rules']
        deleted = False
        for rule in rules:
            for action_block in rule['Actions']:
                if (action_block['Type'] == 'redirect'
                        and action_block['RedirectConfig'].get('Host') == s3_host):
                    elbv2.delete_rule(RuleArn=rule['RuleArn'])
                    deleted = True
        return {"result": "Maintenance mode OFF", "deleted": deleted}