from endpoints import User, NotFound
import urllib.request
import boto3
import json
import re
import os


AUTH_SERVER = os.environ['AuthServer']


def get_claims(token):
    req = urllib.request.Request(
        url=AUTH_SERVER+'/oauth2/v1/userinfo',
        headers={'Authorization': f'Bearer {token}'},
        method='GET'
    )
    res = urllib.request.urlopen(req, timeout=3)
    if res.status == 200:
        return json.loads(res.read().decode('utf-8'))
    print(res.reason)
    raise Exception('Unable to retrieve claims')


def authorize(event, context):
    claims = get_claims(
        event["authorizationToken"]
    )

    methods = []
    context = {}
    if 'groups' in claims:
        if 'Member' in claims['groups']:
            context = {'email': claims['email'], 'role': 'member', 'profileId': ''}
            methods.extend([[HttpVerb.GET, "/user"]])
            methods.extend([[HttpVerb.GET, "/directory"]])
    else:
        try:
            user = User(claims['email'])
        except NotFound:
            raise Exception('Unauthorized')
        context = {'email': user.email, 'role': user.role, 'profileId': user.profileId}
        methods.extend([[HttpVerb.GET, "/user"]])
        methods.extend([[HttpVerb.GET, "/directory"]])
        methods.extend([[HttpVerb.POST, "/comment"]])

    # arn:aws:execute-api:us-east-1:123456789012:s4x3opwd6i/test/GET/request
    tmp = event["methodArn"].split(":")
    awsAccountId = tmp[4]
    apiGatewayArnTmp = tmp[5].split("/")
    
    policy = AuthPolicy(claims["sub"], awsAccountId)
    policy.restApiId = apiGatewayArnTmp[0]
    policy.region = tmp[3]
    policy.stage = apiGatewayArnTmp[1]

    for m in methods:
        policy.allowMethod(m[0], m[1])

    authResponse = policy.build()

    if context:
        authResponse["context"] = context

    return authResponse


class HttpVerb:
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    HEAD = "HEAD"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    ALL = "*"


class AuthPolicy(object):
    awsAccountId = ""
    principalId = ""
    version = "2012-10-17"
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"
    allowMethods = []
    denyMethods = []
    restApiId = "<<restApiId>>"
    region = "<<region>>"
    stage = "<<stage>>"

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError(
                "Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class"
            )
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError(
                "Invalid resource path: "
                + resource
                + ". Path should match "
                + self.pathRegex
            )

        if resource[:1] == "/":
            resource = resource[1:]

        resourceArn = (
            "arn:aws:execute-api:"
            + self.region
            + ":"
            + self.awsAccountId
            + ":"
            + self.restApiId
            + "/"
            + self.stage
            + "/"
            + verb
            + "/"
            + resource
        )

        if effect.lower() == "allow":
            self.allowMethods.append(
                {"resourceArn": resourceArn, "conditions": conditions}
            )
        elif effect.lower() == "deny":
            self.denyMethods.append(
                {"resourceArn": resourceArn, "conditions": conditions}
            )

    def _getEmptyStatement(self, effect):
        statement = {
            "Action": "execute-api:Invoke",
            "Effect": effect[:1].upper() + effect[1:].lower(),
            "Resource": [],
        }
        return statement

    def _getStatementForEffect(self, effect, methods):
        statements = []
        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)
            for curMethod in methods:
                if curMethod["conditions"] is None or len(curMethod["conditions"]) == 0:
                    statement["Resource"].append(curMethod["resourceArn"])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement["Resource"].append(curMethod["resourceArn"])
                    conditionalStatement["Condition"] = curMethod["conditions"]
                    statements.append(conditionalStatement)
            statements.append(statement)
        return statements

    def allowAllMethods(self):
        self._addMethod("Allow", HttpVerb.ALL, "*", [])

    def denyAllMethods(self):
        self._addMethod("Deny", HttpVerb.ALL, "*", [])

    def allowMethod(self, verb, resource):
        self._addMethod("Allow", verb, resource, [])

    def denyMethod(self, verb, resource):
        self._addMethod("Deny", verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        self._addMethod("Allow", verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        self._addMethod("Deny", verb, resource, conditions)

    def build(self):
        if (self.allowMethods is None or len(self.allowMethods) == 0) and (
            self.denyMethods is None or len(self.denyMethods) == 0
        ):
            raise NameError("No statements defined for the policy")

        policy = {
            "principalId": self.principalId,
            "policyDocument": {"Version": self.version, "Statement": []},
        }

        policy["policyDocument"]["Statement"].extend(
            self._getStatementForEffect("Allow", self.allowMethods)
        )
        policy["policyDocument"]["Statement"].extend(
            self._getStatementForEffect("Deny", self.denyMethods)
        )

        return policy


if __name__ == "__main__":
    f = open("auth_request.json")
    req = json.load(f)
    f.close()

    policy = authorize(req, None)

    print(json.dumps(policy, indent=2))
