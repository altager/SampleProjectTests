import unittest
import logging
import requests
import json
import time

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M')


def logging_test_names(f):
    def wrapped(self):
        logging.log(logging.INFO, "{0} started".format(f.__name__))
        f(self)
    return wrapped


def data_creator(username, email, password, data_type="users"):
    template = {'data': {'type': data_type, 'attributes': {'email': email, 'username': username, 'password': password}}}
    return json.dumps(template)


class SampleProjectApiTests(unittest.TestCase):
    url = "http://ec2-52-28-4-254.eu-central-1.compute.amazonaws.com/users/"
    email_domain = "@test.com"
    user_details = None
    data_stub = "stub{0}".format(str(int(time.time())))
    default_headers = {'Content-Type': 'application/vnd.api+json'}

    @logging_test_names
    def test_01_user_should_be_created(self):
        r = requests.post(self.url,
                          data=data_creator(self.data_stub, self.data_stub + self.email_domain, self.data_stub),
                          headers=self.default_headers)
        self.assertTrue(r.status_code == 201)
        self.__class__.user_details = json.loads(r.text)
        self.assertTrue(self.user_details['data']['attributes']['username'] == self.data_stub)
        self.assertTrue(self.user_details['data']['attributes']['email'] == self.data_stub + self.email_domain)

    @logging_test_names
    def test_02_login_already_used_error_should_appear(self):
        r = requests.post(self.url,
                          data=data_creator(self.data_stub, "not_used_email" + self.email_domain, self.data_stub),
                          headers=self.default_headers)
        self.assertTrue(r.status_code == 409)
        self.assertTrue("login_already_used" == json.loads(r.text)['errors'][0]['code'])

    @logging_test_names
    def test_03_password_less_than_5_characters_error_should_appear(self):
        r = requests.post(self.url,
                          data=data_creator("not_used_username", "not_used_email" + self.email_domain, "1"),
                          headers=self.default_headers)
        self.assertTrue(r.status_code == 422)
        self.assertTrue("invalid_parameter_value" == json.loads(r.text)['errors'][0]['code'])

    @logging_test_names
    def test_04_bad_data_type_error_should_appear(self):
        r = requests.post(self.url,
                          data=data_creator("not_used_username", "not_used_email" + self.email_domain,
                                            self.data_stub, data_type='bad_type'),
                          headers=self.default_headers)
        self.assertTrue(r.status_code == 400)
        self.assertTrue("invalid_type" == json.loads(r.text)['errors'][0]['code'])

    @logging_test_names
    def test_05_bad_content_type_error_should_appear(self):
        r = requests.post(self.url,
                          data=data_creator("not_used_username", "not_used_email" + self.email_domain, self.data_stub),
                          headers={'Content-Type': 'Bad type'})
        self.assertTrue(r.status_code == 415)

    @logging_test_names
    def test_06_bad_request_error_should_appear(self):
        r = requests.post(self.url,
                          data=json.dumps({}),
                          headers=self.default_headers)
        self.assertTrue(r.status_code == 422)
        self.assertTrue("malformed_request" == json.loads(r.text)['errors'][0]['code'])

    @logging_test_names
    def test_07_email_already_used_error_should_appear(self):
        r = requests.post(self.url,
                          data=data_creator("not_used_login", self.data_stub + self.email_domain, self.data_stub),
                          headers=self.default_headers)
        self.assertTrue(r.status_code == 409)
        self.assertTrue("email_already_used" == json.loads(r.text)['errors'][0]['code'])

    @logging_test_names
    def test_08_user_not_found_error_should_appear(self):
        r = requests.get(self.url + "99999", params={'requested_user': '99999'}, headers=self.default_headers)
        self.assertTrue(r.status_code == 404)
        self.assertTrue("user_not_found" == json.loads(r.text)['errors'][0]['code'])

    @logging_test_names
    def test_09_user_info_should_be_retrieved(self):
        username = self.user_details['data']['attributes']['username']
        r = requests.get(self.url + username, params={'requested_user': username}, headers=self.default_headers)
        self.assertTrue(r.status_code == 200)
        del self.user_details['data']['attributes']['email']
        self.assertTrue(self.user_details['data']['attributes'] == json.loads(r.text)['data']['attributes'])

    @logging_test_names
    def test_10_json_parse_error_should_appear(self):
        r = requests.post(self.url,
                          data={},
                          headers=self.default_headers)
        self.assertTrue(r.status_code == 400)
        self.assertTrue("json_parse_error" == json.loads(r.text)['errors'][0]['code'])

    @logging_test_names
    def test_11_chat_color_should_be_updated(self):
        r = requests.patch(self.url + self.user_details['data']['id'],
                           data=json.dumps({'data': {'type': 'users', 'attributes': {'chat_username_color': '#4286f4'}}}),
                           headers=self.default_headers)
        self.assertTrue(r.status_code == 204)
        r = requests.get(self.url + self.user_details['data']['attributes']['username'])
        self.assertTrue(r.status_code == 200)
        self.assertTrue('#4286f4' == json.loads(r.text)['data']['attributes']['chat_username_color'])

    #Here is the problem. Error 500
    @logging_test_names
    def test_12_username_of_user_requested_by_username_should_be_updated(self):
        new_username = "stub{0}".format(str(int(time.time())))
        #If im using 'id' - test passed.
        r = requests.patch(self.url + self.user_details['data']['attributes']['username'],
                           data=json.dumps({'data': {'type': 'users', 'attributes': {'username': new_username}}}),
                           headers=self.default_headers)
        self.assertTrue(r.status_code == 204)
        r = requests.get(self.url + new_username, params={'requested_user': new_username})
        self.assertTrue(r.status_code == 200)
        self.assertTrue(new_username == json.loads(r.text)['data']['attributes']['username'])
