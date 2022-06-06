from decimal import Decimal
import boto3
import json
import os

REGION = "us-east-1"
DB = boto3.resource("dynamodb", region_name=REGION)
USERS = DB.Table(os.environ["UserTable"])
PROFILES = DB.Table(os.environ["ProfilesTable"])


class DecimalEncoder(json.JSONEncoder):
    """handle dynamoDB decimals"""

    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj)
        return json.JSONEncoder.default(self, obj)


class NotFound(Exception):
    pass


class Directory:
    def __init__(self, user, active=True):
        # TODO filter active
        self.user = user
        self.profiles = []
        profiles = PROFILES.scan()["Items"]
        for p in profiles:
            self.profiles.append(
                Profile(user, profile=p)._dict()
            )

    def _dict(self):
        return self.profiles


class Profile:
    def __init__(self, user, profileId=None, profile=None):
        if profileId:
            self._parse(user, PROFILES.get_item(Key={"id": profileId}))
        elif profile:
            self._parse(user, profile)

    def _parse(self, user, profile):
        self.user = user
        self.id = str(profile["id"])
        self.logo = profile["logo"]
        self.short = profile["short"]
        self.status = profile["status"]
        self.tags = profile["tags"]
        self.title = profile["title"]
        if "votes" in profile:
            self.votes = len(profile["votes"])
        else:
            self.votes = 0
        if "comments" in profile:
            self.comments = self._anonymize_comments(user, profile["comments"])
        else:
            self.comments = []
        if user['role'] == 'member':
            self.desc = profile["desc"]
        # only include desc for the editor's profile
        elif user['role'] == 'editor' and user['profileId'] == self.id:
            self.desc = profile["desc"]
        else:
            self.desc = ''

    def _anonymize_comments(self, user, comments):
        anon_comments = []
        for c in comments:
            if c["user"] == user['email']:
                anon_comments.append(c)
            else:
                c["user"] = "anonymous"
                anon_comments.append(c)
        return anon_comments

    def _save(self):
        # update dynamoDB
        pass

    def comment(self, comment):
        # TODO safety check comment
        comments = self.comments
        # remove existing comments
        for i, c in enumerate(self.comments):
            if c["user"] == self.user['email']:
                comments.pop(i)
        # add comment
        comments.append({'user': self.user['email'], 'comment': comment})
        self.comments = comments
        self._save()


    def _dict(self):
        return {
            "id": self.id,
            "desc": self.desc,
            "logo": self.logo,
            "short": self.short, 
            "status": self.status,
            "tags": self.tags,
            "title": self.title,
            "votes": self.votes,
            "comments": self.comments
        }


class User:
    def __init__(self, email=None):
        if email:
            user = USERS.get_item(Key={"user": email})
            if "Item" not in user:
                raise NotFound(email)
            self.email = user["Item"]["user"]
            self.role = user["Item"]["role"]
            if "profileId" in user["Item"]:
                self.profileId = user["Item"]["profileId"]
            else:
                self.profileId = ''
            if "votes" in user["Item"]:
                self.votes = user["Item"]["votes"]
            else:
                self.votes = []
            if "comments" in user["Item"]:
                self.comments = user["Item"]["comments"]
            else:
                self.comments = []

    def _dict(self):
        return {
            "email": self.email,
            "role": self.role,
            "profileId": self.profileId,
            "votes": self.votes,
            "comments": self.comments,
        }


def response(code=200, msg="ok", headers=None):
    default_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": os.environ["Origin"].replace("'", ""),
        "Access-Control-Allow-Credentials": True,
    }
    if headers:
        default_headers.update(headers)
    return {
        "statusCode": code,
        "body": json.dumps(msg, cls=DecimalEncoder),
        "headers": default_headers,
    }


def get_user(evt, c):
    email = evt["requestContext"]["authorizer"]["email"]
    user = User(email)
    return response(code=200, msg=user._dict())


def get_directory(evt, c):
    user = evt["requestContext"]["authorizer"] # email, role, profileId
    directory = Directory(user)
    return response(code=200, msg=directory._dict())

def update_comment(evt, c):
    try:
        user = evt["requestContext"]["authorizer"]
        body = json.loads(evt['body'])
        profileId = body['profileId']
        comment = body['comment']
    except:
        return response(code=201, msg={'error': 'bad payload'})
    profile = Profile(user, profileId)
    profile.comment(comment)
    return response(code=200, msg=profile._dict())