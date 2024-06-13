import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import requests


import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


''' CLIENT CLASS '''


class Client(BaseClient):
    def get_request(self, param: Dict):
        return self._http_request(
            method='GET',
            params=param,
            resp_type='response'
        )


''' HELPER FUNCTIONS '''


def sort_data_helper(content: List, args: Dict) -> List:
    try:
        if args.get('sort') == 'desc':
            sorted_data = sorted(content,
                                 key=lambda x: datetime.strptime(x['LAST_MODIFIED'],"%Y-%m-%dT%H:%M:%S.%fZ"),
                                 reverse=True)
        else:
            sorted_data = sorted(content,
                                 key=lambda x: datetime.strptime(x['LAST_MODIFIED'], "%Y-%m-%dT%H:%M:%S.%fZ"),
                                 reverse=False)
        return sorted_data

    except DemistoException as error:
        raise error


def custom_send_events_to_xsiam(params: Dict, pdns_events: List) -> str:
    try:
        headers = {
            'Authorization': params.get('xsiam_api'),
            'Content-Type': 'application/json'
        }

        res = requests.post(urljoin(params.get('xsiam_url'), '/logs/v1/event'),
                            headers=headers,
                            data=' '.join(json.dumps(event) for event in pdns_events))

        if not res.ok:
            raise DemistoException('Could not push data to PDNS dataset. {0} - {1}'
                                   .format(res.status_code, res.text))

    except DemistoException as error:
        raise error


''' COMMAND FUNCTIONS '''


def test_module(client: Client, req_param: Dict) -> str:
    try:
        res = client.get_request(req_param)
        if res.ok:
            return 'ok'
        else:
            return 'Test Command Error: {0} - {1}'.format(res.status_code, res.text)
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_links(client: Client, req_param: Dict, args: Dict) -> CommandResults:
    try:
        res = client.get_request(req_param)
        if res.ok:
            content = res.json().get('body').get('data')
            if len(content) > 0:
                sorted_data = sort_data_helper(content, args)

                return CommandResults(
                    readable_output=tableToMarkdown('PDNS Event Links', sorted_data),
                    outputs_prefix='PDNS.Link',
                    outputs_key_field='',
                    outputs=sorted_data,
                    raw_response=res.json()
                )
            else:
                return CommandResults(
                    readable_output='No new Event Links received.'
                )
        else:
            raise DemistoException('Could not receive data from PDNS. {0} - {1}'
                                   .format(res.status_code, res.text))

    except DemistoException as error:
        raise error


def get_logs(link: str) -> CommandResults:
    try:
        res = requests.get(link)

        if res.ok:
            content = res.json()
            return CommandResults(
                readable_output=tableToMarkdown('PDNS Logs', content),
                outputs_prefix='PDNS.Log',
                outputs_key_field='',
                outputs=content,
                raw_response=res.json()
            )
        else:
            raise DemistoException('Could not receive data from PDNS. {0} - {1}'
                                   .format(res.status_code, res.text))

    except DemistoException as error:
        raise error


def fetch_events(client: Client, req_param: Dict, last_run: Dict):
    try:
        last_modified = last_run.get('LAST_MODIFIED') if last_run else None
        events = []

        res = client.get_request(req_param)
        if res.ok:
            content = res.json().get('body').get('data')
            args = {'sort': 'desc'}
            if len(content) > 0:
                sorted_data = sort_data_helper(content, args)

                for data in sorted_data:
                    if data.get('LAST_MODIFIED') == last_modified:
                        break
                    else:
                        res = requests.get(data.get('LINK_URL'))
                        events.append(res.json())

                last_modified = sorted_data[0].get('LAST_MODIFIED')

            return last_modified, events

        else:
            raise DemistoException('Could not receive data from PDNS. {0} - {1}'
                                   .format(res.status_code, res.text))

    except DemistoException as error:
        raise error


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    base_url = params.get('url')
    accesskey = params.get('credentials', {}).get('identifier')
    secretkey = params.get('credentials', {}).get('password')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {
            'content-type': 'application/json'
        }

        req_params = {
            'accesskeyid': accesskey,
            'secretkey': secretkey
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client, req_params))
        elif demisto.command() == 'get-links':
            return_results(get_links(client, req_params, args))
        elif demisto.command() == 'get-logs':
            return_results(get_logs(args.get('link')))
        elif demisto.command() == 'fetch-incidents':
            last_run = demisto.getLastRun()
            logs_next_run, pdns_events = fetch_events(client, req_params, last_run)
            custom_send_events_to_xsiam(params, pdns_events)
            demisto.setLastRun({'LAST_MODIFIED': logs_next_run})
            demisto.updateModuleHealth({'{data_type}Pulled'.format(data_type='EVENTS'): len(pdns_events)})
            #demisto.incidents(pdns_events)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

