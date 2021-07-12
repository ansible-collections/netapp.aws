# Copyright (c) 2018 NetApp
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

''' unit tests for module_utils netapp.py '''
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os.path
import tempfile

import pytest

from ansible.module_utils import basic
from ansible.module_utils._text import to_bytes
from ansible_collections.netapp.aws.tests.unit.compat.mock import patch

import ansible_collections.netapp.aws.plugins.module_utils.netapp as netapp_utils


def set_module_args(args):
    """prepare arguments so that they will be picked up during module creation"""
    args = json.dumps({'ANSIBLE_MODULE_ARGS': args})
    basic._ANSIBLE_ARGS = to_bytes(args)  # pylint: disable=protected-access


class AnsibleFailJson(Exception):
    """Exception class to be raised by module.fail_json and caught by the test case"""


def fail_json(*args, **kwargs):  # pylint: disable=unused-argument
    """function to patch over fail_json; package return data into an exception"""
    kwargs['failed'] = True
    raise AnsibleFailJson(kwargs)


SRR = {
    'empty_good': (dict(), None),
    'get_data': (dict(records=['data1', 'data2']), None),
    'end_of_sequence': (None, "Unexpected call to send_request"),
    'generic_error': (None, "Expected error"),
}


def mock_args(feature_flags=None):
    args = {
        'api_key': 'api_key',
        'api_url': 'api_url',
        'secret_key': 'secret_key!',
    }
    if feature_flags is not None:
        args.update({'feature_flags': feature_flags})
    return args


def create_module(args):
    argument_spec = netapp_utils.aws_cvs_host_argument_spec()
    set_module_args(args)
    module = basic.AnsibleModule(argument_spec)
    return module


def create_restapi_object(args):
    module = create_module(args)
    module.fail_json = fail_json
    rest_api = netapp_utils.AwsCvsRestAPI(module)
    return rest_api


class mockResponse:
    def __init__(self, json_data, status_code, raise_action=None):
        self.json_data = json_data
        self.status_code = status_code
        self.content = json_data
        self.raise_action = raise_action

    def raise_for_status(self):
        pass

    def json(self):
        if self.raise_action == 'bad_json':
            raise ValueError(self.raise_action)
        return self.json_data


@patch('ansible_collections.netapp.aws.plugins.module_utils.netapp.AwsCvsRestAPI.send_request')
def test_empty_get(mock_request):
    ''' get with no data '''
    mock_request.side_effect = [
        SRR['empty_good'],
        SRR['end_of_sequence'],
    ]
    rest_api = create_restapi_object(mock_args())
    message, error = rest_api.get('api', None)
    assert not error
    assert len(message) == 0


@patch('ansible_collections.netapp.aws.plugins.module_utils.netapp.AwsCvsRestAPI.send_request')
def test_get_data(mock_request):
    ''' get with data '''
    mock_request.side_effect = [
        SRR['get_data'],
        SRR['end_of_sequence'],
    ]
    rest_api = create_restapi_object(mock_args())
    message, error = rest_api.get('api', None)
    assert not error
    print('get:', message)
    assert message['records'] == SRR['get_data'][0]['records']


def test_has_feature_success_default_0():
    ''' existing feature_flag with default of False'''
    flag = 'trace_apis'
    module = create_module(mock_args())
    value = netapp_utils.has_feature(module, flag)
    assert not value


def test_has_feature_success_default_1():
    ''' existing feature_flag with default of True'''
    flag = 'strict_json_check'
    module = create_module(mock_args())
    value = netapp_utils.has_feature(module, flag)
    assert value


def test_has_feature_success_user_true():
    ''' existing feature_flag with value set to True '''
    flag = 'user_deprecation_warning'
    args = dict(mock_args({flag: True}))
    module = create_module(args)
    value = netapp_utils.has_feature(module, flag)
    assert value


def test_has_feature_success_user_false():
    ''' existing feature_flag with value set to False '''
    flag = 'user_deprecation_warning'
    args = dict(mock_args({flag: False}))
    print(args)
    module = create_module(args)
    value = netapp_utils.has_feature(module, flag)
    assert not value


def test_has_feature_invalid_key():
    ''' existing feature_flag with unknown key '''
    flag = 'deprecation_warning_bad_key'
    module = create_module(mock_args())
    # replace ANsible fail method with ours
    module.fail_json = fail_json
    with pytest.raises(AnsibleFailJson) as exc:
        netapp_utils.has_feature(module, flag)
    msg = 'Internal error: unexpected feature flag: %s' % flag
    assert exc.value.args[0]['msg'] == msg


@patch('requests.request')
def test_empty_get_sent(mock_request):
    ''' get with no data '''
    mock_request.return_value = mockResponse(json_data=dict(_links='me'), status_code=200)
    rest_api = create_restapi_object(mock_args())
    message, error = rest_api.get('api', None)
    assert not error
    # only one key (_links)
    assert len(message) == 1


@patch('requests.request')
def test_empty_get_sent_bad_json(mock_request):
    ''' get with no data '''
    mock_request.return_value = mockResponse(json_data='anything', status_code=200, raise_action='bad_json')
    rest_api = create_restapi_object(mock_args())
    message, error = rest_api.get('api', None)
    assert error
    assert 'Expecting json, got: anything' in error
    print('errors:', rest_api.errors)
    print('debug:', rest_api.debug_logs)


@patch('requests.request')
def test_empty_get_sent_bad_but_empty_json(mock_request):
    ''' get with no data '''
    mock_request.return_value = mockResponse(json_data='', status_code=200, raise_action='bad_json')
    rest_api = create_restapi_object(mock_args())
    message, error = rest_api.get('api', None)
    assert error is None
    assert message is None
