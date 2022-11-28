#!/usr/bin/env python3

from __future__ import annotations
import argparse
import getopt
import glob
import json
from collections import defaultdict
import os.path
import os
import pprint
from datetime import date
import subprocess
import sys
import xml.etree.ElementTree as ET

import yaml

try:
    import jamf
    jamf_mod_avail = True
except ModuleNotFoundError:
    jamf_mod_avail = False
import readline
from pathlib import Path

file_path = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(file_path)



def root_folder():
    # return Path(os.path.realpath(os.path.dirname(__file__))).parents[0]
    return parent_dir

import generate_guidance

class textcolors:
    HEADER = '\033[95m'
    BACKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    NEWGREEN = '\033[92m'
    WARNING = '\033[93m'
    DELETERED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class MyCompleter(object):    
    def __init__(self, options):
        self.options = sorted(options)
        return        
    def complete(self, text, state):
        response = None
        if state == 0:
            if text:
                self.matches = [s 
                    for s in self.options 
                    if s and s.startswith(text)]
            else:
                self.matches = self.options[:]
        try:
            response = self.matches[state]
        except IndexError:
            response = None
        return response

class YamlSource():

    def __init__(self, yaml_location=None, yaml_stream=None):
        if yaml_location is None:
            yaml_location = ""
        self._yaml_location = yaml_location
        if yaml_stream is None:
            yaml_stream = {}
        self._yaml_stream = yaml_stream

    def set_yaml_location(self, file_path):
        self._yaml_location = file_path

    def get_yaml_location(self):
        return self._yaml_location

    def set_yaml_stream(self, stream):
        self._yaml_stream = stream

    def get_yaml_stream(self):
        return self._yaml_stream

    def loadYAML(self):
        try:
            with open(self.get_yaml_location()) as r:
                self.set_yaml_stream(yaml.load(r, Loader=yaml.SafeLoader))
        except OSError as error:
            print(f'{error} YAML file could not be loaded.')
        except yaml.YAMLError as error:
            print(f"{error} YAML not proper")
        except:
            print("error")
        if not self.get_yaml_stream():
            return False, "error"
        else:
            return True, self.get_yaml_stream()

    def writeYAML(self, outfile, my_dict):
        try:
            with open(outfile, 'w') as file:
                yaml.dump(my_dict, file)
        except:
            print("error")

class MSCPBaseline(YamlSource):
    def __init__(self, baseline_except_folder=None):
        if baseline_except_folder is None:
            baseline_except_folder = ""
        self._baseline_except_folder = baseline_except_folder

    @classmethod
    def baselines_files(cls):
        baseline_root = os.path.join(root_folder(), 'build', 'baselines')
        return glob.glob(os.path.join(baseline_root, '*.yaml'))

    def select_baseline(self):
        bl_count = len(MSCPBaseline.baselines_files())
        exit_num = bl_count + 1
        if bl_count == 0:
            print("A built baseline is required. Please visit <mSCP URL goes here> for instructions setting up.")
            sys.exit()
        while True:
            print(f'{bl_count} baseline(s) found')
            print("Select the baseline for your exceptions\n")
            for index, bl in enumerate(MSCPBaseline.baselines_files()):
                bl_name = os.path.basename(bl).split('.')[0]
                menu_num = index + 1
                print(f'{menu_num} -- {bl_name}')
            print(f'{exit_num} -- Exit')
            while True:
                try:
                    selection = int(input("Select number: "))
                    break
                except ValueError:
                    print("Please enter a number.")
            if int(selection) <= bl_count and int(selection) > 0:
                self.set_yaml_location(MSCPBaseline.baselines_files()[int(selection) - 1])
                ExceptionPreferences.writeBaselineLocation(self.get_yaml_location())
                self.set_baseline_exemption_folder()
                break
            else:
                print("Exiting...")
                sys.exit()

    def set_baseline_exemption_folder(self):
        # baseline_except_path = os.path.join(os.path.join(os.path.realpath(os.path.dirname(__file__)), os.pardir), self.get_baseline_name())
        baseline_except_path = os.path.join(root_folder(), 'build', self.get_baseline_name(), 'exemptions')
        if not os.path.exists(baseline_except_path):
            os.mkdir(baseline_except_path)
        self._baseline_except_folder = baseline_except_path

    def get_baseline_exempt_folder(self):
        return self._baseline_except_folder

    def get_current_exemptions(self):
        return glob.glob(os.path.join(self.get_baseline_exempt_folder(), '*.yaml'))

    def get_baseline_name(self):
        return os.path.basename(self.get_yaml_location()).split('.')[0]

    def get_rule_list(self):
        rule_list = []
        self.loadYAML()
        for sections in self.get_yaml_stream()['profile']:
            for profile_rule in sections['rules']:
                rule_list.append(profile_rule)
                # print(profile_rule)
        # print(rule_list)
        return rule_list
    
    def get_pref_domains(self):
        domain_list = []
        for item in self.get_rule_list():
            # print(item)
            try:
                rule = MSCPSecurityRule(item)
                rule.loadYAML()
                # print(rule.get_yaml_location())
                if rule.is_mobileconfig():
                    for domain in rule.pref_domains():
                        domain_list.append(domain)
            except IndexError as e:
                print(f'gpd{e} for {item}')
        return domain_list
    
    def rules_not_in_exemptions(self):
        rules = []
        for rule in self.get_rule_list():
            if rule not in self.all_exemption_rules():
                rules.append(rule)
        # print(rules)
        return rules

    
    def pref_conflicts(self):
        prefs = []
        ni_domain_list = []
        for rule_id in self.rules_not_in_exemptions():
            # print(rule_id)
            try:
                rule = MSCPSecurityRule(rule_id)
                rule.loadYAML()
                if rule.is_mobileconfig():
                    for domain, pkeys in rule.get_yaml_stream()['mobileconfig_info'].items():
                        ni_domain_list.append(domain)
            except IndexError:
                print('Index Error')

        for exemption in self.all_exemption_domains():
            for exemption_id, rule_list in exemption.items():
                temp_dict = inf_ddict()
                for rule_id, domain_settings in rule_list.items():
                    for domain, domain_prefs in domain_settings.items():
                        if domain in ni_domain_list:
                            temp_dict[exemption_id][rule_id][domain] = domain_prefs
            temp_dict = json.loads(json.dumps(temp_dict))
            prefs.append(temp_dict)
        return prefs
    
    def generate_non_exempt_pofiles(self):
        profiles_array = []
        unique_domains =[]
        # pprint.pprint(self.get_pref_domains())
        [unique_domains.append(x) for x in self.get_pref_domains() if x not in unique_domains]
        for domain in unique_domains:
            try:
                pref = PrefDomain(domain)
                profiles_array.append(pref.exclude_exemption_rules(self))
            except IndexError as e:
                print(f'gnep{e}')
        return profiles_array

    def display_domain_conflicts(self):
        if len(self.pref_conflicts()) > 0:
                print('\nThe baseline exemptions contain the following config profile conflicts:\n')
                for conflict in self.pref_conflicts():
                    for exemption_id, rules in conflict.items():
                        for rule_id, domains in rules.items():
                            for domain, prefs in domains.items():
                                print(f'{textcolors.NEWGREEN}Exemption:{textcolors.ENDC} {exemption_id} | {textcolors.NEWGREEN}Rule:{textcolors.ENDC} {rule_id} | {textcolors.NEWGREEN}Domain:{textcolors.ENDC} {domain} | {textcolors.NEWGREEN}Settings:{textcolors.ENDC} {prefs}')
                print("")
        else:
            print('\nNo current preference domain conflicts\n')
        input('Press enter to continue')        
    
    def all_exemption_rules(self):
        paths = glob.glob(os.path.join(self.get_baseline_exempt_folder(), '*.yaml'))
        rules = []
        for path in paths:
            exemption = MSCPExemption()
            exemption.set_yaml_location(path)
            exemption.loadYAML()
            for rule in exemption.get_yaml_stream()['rules']:
                rules.append(rule)
        return rules
    
    def all_exemption_domains(self):
        paths = glob.glob(os.path.join(self.get_baseline_exempt_folder(), '*.yaml'))
        domains = []
        for path in paths:
            exemption = MSCPExemption()
            exemption.set_yaml_location(path)
            exemption.loadYAML()
            domains.append(exemption.domains_in_exemption())
        return domains
            
    def show_exemptions_list(self):
        while True:
            print("\nSelect a current exemption or new to continue\n")
            exc_count = len(self.get_current_exemptions())
            os.system('clear')
            print(f'{textcolors.UNDERLINE}Exemptions for {self.get_baseline_name()}{textcolors.ENDC}\n')
            print(f'1 -- {textcolors.NEWGREEN}Create New Exception{textcolors.ENDC}')
            exception_list = []
            for index, exempt in enumerate(self.get_current_exemptions()):
                exception_list.append(exempt)
                exec_name = os.path.basename(exempt).split('.')[0]
                menu_num = index + 2
                print(f'{menu_num} -- {exec_name}')
            print(f'{exc_count + 2} -- {textcolors.BACKBLUE}Back{textcolors.ENDC}')
            while True:
                try:
                    selection = int(input("\nSelect number: "))
                    break
                except ValueError:
                    print("Please enter a number.")
            if int(selection) <= exc_count + 1 and int(selection) > 1:
                exemption = MSCPExemption()
                exemption.set_yaml_location(exception_list[int(selection) - 2])
                exemption.edit_exemption(self)
            elif int(selection) == 1:
                new_exemption = MSCPExemption()
                new_exemption.create_new_exemption(self)
            else:
                break

class MSCPExemption(YamlSource):
    def __init__(self):
        self.exception_dict={}
    
    def edit_exemption(self, baseline):
        while True:
            err, self.exception_dict = self.loadYAML()
            print(f"\nEditing exemption for id: {self.exception_dict['id']}\n")
            print("1 -- Edit name")
            print("2 -- Edit description")
            print("3 -- Edit type")
            print("4 -- Add or delete rules")
            print(f"5 -- {textcolors.DELETERED}Delete exemption definition{textcolors.ENDC}")
            print("6 -- Back")
            while True:
                try:
                    selection = int(input("\nEnter selection: "))
                    break
                except ValueError:
                    print('Please enter a number.')
            if int(selection) == 1:
                print(f"\nCurrent name: {self.exception_dict['name']}")
                new_name = input("Enter new name: ")
                self.exception_dict['name'] = new_name
                self.writeYAML(self.get_yaml_location(), self.exception_dict)
                self.set_yaml_stream(self.exception_dict)
                print(f"\nException {self.exception_dict['id']} updated")            
            elif int(selection) == 2:
                print(f"\nCurrent description: {self.exception_dict['description']}")
                new_desc = input("Enter new description: ")
                self.exception_dict['description'] = new_desc
                self.writeYAML(self.get_yaml_location(), self.exception_dict)
                self.set_yaml_stream(self.exception_dict)
                print(f"\nException {self.exception_dict['id']} updated")                
            elif int(selection) == 3:
                print(f"\nCurrent type: {self.exception_dict['type']}")
                self.set_exempt_type()                    
            elif int(selection) == 4:
                while True:
                    print(f"Editing rule list for exception id: {self.exception_dict['id']}\n")
                    print(f"1 -- {textcolors.NEWGREEN}Add new rule{textcolors.ENDC}")
                    for index, rule in enumerate(self.exception_dict['rules']):
                        print(f"{index + 2} -- {textcolors.DELETERED}Delete rule {rule}{textcolors.ENDC}")
                    print(f"{len(self.exception_dict['rules']) + 2} -- {textcolors.BACKBLUE}Back{textcolors.ENDC}")
                    selection = input("\n Select number: ")
                    if int(selection) == 1:
                        self.add_rule(baseline)
                    elif int(selection) > 1 and int(selection) < len(self.exception_dict['rules']) + 2:
                        print(f"{textcolors.DELETERED}Deleting {self.exception_dict['rules'][int(selection) - 2]}{textcolors.ENDC}")
                        self.exception_dict['rules'].remove(f"{self.exception_dict['rules'][int(selection) - 2]}")
                    else:
                        break                        
                self.writeYAML(self.get_yaml_location(), self.exception_dict)
                self.set_yaml_stream(self.exception_dict)
                print(f"\nException {self.exception_dict['id']} updated")                
            elif int(selection) == 5:
                os.system('clear')
                print(f"{textcolors.WARNING}Are you sure you want to delete {self.exception_dict['id']} {textcolors.ENDC}")
                conf = input("(y/n): ")
                if conf == 'y':
                    print("Deleting file.....")
                    if os.path.exists(self.get_yaml_location()):
                        os.remove(self.get_yaml_location())
                        
                        print(f"\nException {self.exception_dict['id']} deleted")
                        break
                    else:
                        print("File doesn't exist")
            else:
                break                        
                
    def create_new_exemption(self, baseline):        
        while True:
            os.system('clear')
            try:
                except_id = input("Enter id for exception: ")
                if not except_id:
                    print("ID required. Returning to exceptions list.")
                    break
                for c in except_id:
                    if c.isspace():
                        raise TypeError()                
                for exc in baseline.get_current_exemptions():
                    if os.path.basename(exc).split('.')[0] == except_id:
                        raise ValueError()                
            except TypeError:
                print("Exception ID cannot have spaces. It is recommended to use _ instead.")                
            except ValueError:
                print("Exception already exists. Please Enter a new name.")                
            else:
                self.exception_dict['id'] = except_id
                break            
        while True:
            try:
                except_name = input("Enter a friendly name for the exception list: ")
            except:
                print("An error occurred")
            else:
                self.exception_dict['name'] = except_name
                break        
        while True:
            try:
                except_disc = input("Enter a description for the exception list: ")
            except:
                print("An error occurred")
            else:
                self.exception_dict['description'] = except_disc
                break                
        self.set_exempt_type()                
        self.add_rule(baseline)
        
    def set_exempt_type(self):
        while True:
            try:
                except_type = input("Select an exception list type standard (s) or optional (o): ")
                if except_type == 'o' or except_type == 'optional':
                    self.exception_dict['type'] = 'optional'
                    break
                elif except_type == 's' or except_type == 'standard':
                    self.exception_dict['type'] = 'standard'                    
                    break
                else:
                    raise ValueError()
            except ValueError:
                print("Type can only be standard (s) or optional (o)")
                
    def add_rule(self, baseline):
        while True:
            try:
                readline.parse_and_bind("bind ^I rl_complete")
                completer = MyCompleter(baseline.get_rule_list())
                readline.set_completer(completer.complete)
                rule = input("\nEnter rule to add to the exception or 'done' to finish exemption list\n(Tab-complete enabled):")
                if rule in baseline.get_rule_list() or rule == 'done':
                    if rule == 'done':
                        my_path = os.path.join(baseline.get_baseline_exempt_folder(), f"{self.exception_dict['id']}.yaml")
                        self.writeYAML(my_path, self.exception_dict)
                        break
                    elif rule not in baseline.all_exemption_rules():
                        if not "rules" in self.exception_dict.keys():  
                            self.exception_dict['rules'] = [rule]
                            print(f'{rule} added to {self.exception_dict["id"]}')
                        elif not rule in self.exception_dict['rules']:
                            self.exception_dict['rules'].append(rule)
                            print(f'{textcolors.NEWGREEN}{rule} added to {self.exception_dict["id"]}{textcolors.ENDC}')
                    else:
                        print(f"{textcolors.WARNING}Error: Rule exists in another exception.{textcolors.ENDC}")
                else:
                    print(f"{textcolors.WARNING}Error: Rule not in the current baseline.{textcolors.ENDC}")
            except ValueError:
                print("Error: Rule not in baseline or already in exception list")
                
    def domains_in_exemption(self):
        self.get_yaml_location()
        self.loadYAML()
        exemption_id = self.get_yaml_stream()['id']
        domains = []
        domains_dict = inf_ddict()
        test_dict = {}
        for rule_id in self.get_yaml_stream()['rules']:
            rule = MSCPSecurityRule(rule_id)
            rule.set_yaml_location()
            rule.loadYAML()
            rule_id = rule.get_yaml_stream()['id']
            if rule.is_mobileconfig():
                for domain, settings in rule.get_yaml_stream()['mobileconfig_info'].items():
                    for pref, setting in settings.items():
                        domains_dict[exemption_id][rule_id][domain][pref] = setting
        return json.loads(json.dumps(domains_dict))
    
    def settings_for_exemption_domain(self, domain):
        id = self.get_yaml_stream()['id']
        config_settings = {id:{domain:[]}}
        for exempt_id, rules in self.domains_in_exemption().items():
            for rule_id, domains in rules:
                for rule_domain, settings in domains.items():
                    if rule_domain == domain:
                        config_settings[id][domain].append(settings)
        if len(config_settings[id][domain]) == 0:
            return None
        else:
            return config_settings

class PrefDomain:
    def __init__(self, domain) -> None:
        self.domain = domain

    def get_settings_from_rule(self, rule: MSCPSecurityRule):
        return rule.pref_domains()[self.domain]

    def domain_settings(self):
        settings ={}
        return settings

    def get_all_settings_for_baseline(self, baseline: MSCPBaseline):
        domain_dict = {self.domain:{}}
        for rule_id in baseline.get_rule_list():
            rule = MSCPSecurityRule(rule_id)
            rule.set_yaml_location()
            rule.loadYAML()
            if not rule.is_manual() and rule.is_mobileconfig():
                for domain, settings in rule.pref_domains().items():
                    if domain == self.domain:
                        for pref, setting in settings.items():
                            if type(setting) is list:
                                if pref in domain_dict[domain]:
                                    domain_dict[domain][pref].extend(setting)
                                else:
                                    domain_dict[domain].update({pref:setting})
                            else:
                                domain_dict[domain].update({pref:setting})
        return domain_dict
    
    def get_all_settings_for_exemptions(self, exemption: MSCPExemption):
        domain_dict = {self.domain:{}}
        for exemption_id, rules in exemption.domains_in_exemption().items():
            for domains in rules:
                for domain, settings in domains.items():
                    if domain == self.domain:
                        for pref, setting in settings.items():
                            if type(setting) is list:
                                if pref in domain_dict[domain]:
                                    domain_dict[domain][pref].extend(setting)
                                else:
                                    domain_dict[domain].update({pref:setting})
                            else:
                                domain_dict[domain].update({pref:setting})
        return domain_dict

    def exclude_exemption_rules(self, baseline: MSCPBaseline):
        domain_dict = {self.domain:{}}
        for rule_id in baseline.get_rule_list():
            if rule_id not in baseline.all_exemption_rules():
                rule = MSCPSecurityRule(rule_id)
                rule.set_yaml_location()
                rule.loadYAML()
                if not rule.is_manual() and rule.is_mobileconfig():
                    for domain, settings in rule.pref_domains().items():
                        if domain == self.domain:
                            for pref, setting in settings.items():
                                if type(setting) is list:
                                    if pref in domain_dict[domain]:
                                        domain_dict[domain][pref].extend(setting)
                                    else:
                                        domain_dict[domain].update({pref:setting})
                                else:
                                    domain_dict[domain].update({pref:setting})
        return domain_dict

class MSCPSecurityRule(YamlSource):
    def __init__(self, rule_id):
        self.rule = rule_id
        self.set_yaml_location()

    # Send the property from the baseline get_root_folder method. Override to select custom rules automatically
    def set_yaml_location(self):
        file_path = [os.path.abspath(x) for x in
                     glob.glob(os.path.join(parent_dir, 'rules', '*', f'{self.rule}.yaml'), recursive=True)]
        custom_file_path = [os.path.abspath(x) for x in
                            glob.glob(os.path.join(parent_dir, 'custom', 'rules', '*', f'{self.rule}.yaml'),
                                      recursive=True)]
        if custom_file_path.__len__() == 0:
            # print(file_path)
            self._yaml_location = file_path[0]
        else:
            self._yaml_location = custom_file_path[0]

    def get_yaml_stream(self):
        return super().get_yaml_stream()
    
    def is_mobileconfig(self):
        return self.get_yaml_stream()['mobileconfig']
        
    def is_manual(self):
        if 'manual' in self.get_yaml_stream()['tags']:
            return True
        else:
            return False
    
    def pref_domains(self):
        if self.is_mobileconfig():
            return self.get_yaml_stream()['mobileconfig_info']
    
    def process_parameter_value(self, value):
        if value == "$ODV":
            odv_value = self.get_yaml_stream()['odv'][self._baseline.get_yaml_stream()['parent_values']]
            return odv_value
        else:
            return value            
    
class JamfConnect:
    def __init__(self, jamf_api = None):
        self.jamf_api = jamf_api
        
    def get_groups(self):
        group_names = []
        for group in self.jamf_api.get('computergroups')['computer_groups']['computer_group']:
            group_names.append(group['name'])
        return group_names
    
    def group_exists(self, group_name):
        if group_name in self.get_groups():
            return True
        else:
            return False
        
    def jamf_setup_menu(self):
        # Check for a connection
        
        while True:
            trigger, error = ExceptionPreferences.api_token_trigger()
            os.system('clear')
            print(f"\n{textcolors.UNDERLINE}Jamf Connection Settings{textcolors.ENDC}\n")
            print(f"1 -- Test the connection to {self.jamf_api.hostname}")
            if error:
                print("2 -- Set api token policy trigger")
            else:
                print(f"2 -- Modify api token policy trigger ({trigger})")
            print(f"3 -- {textcolors.BACKBLUE}Back{textcolors.ENDC}")
            selection = input("\nEnter number: ")
            if int(selection) == 1:
                print("Testing the connection:")
            elif int(selection) == 2:
                try:
                    new_trigger = input("Enter the new trigger for the token generate policy: ")
                    for c in new_trigger:
                        if c.isspace():
                            raise TypeError()
                except TypeError:
                    print("Jamf trigger cannot have spaces. It is recommended to use _ instead.")
                else:
                    if new_trigger:
                        ExceptionPreferences.write_api_token_trigger(new_trigger)
                    else:
                        print("Trigger unchanged")
                
            elif int(selection) == 3:
                break
            
    def add_static_group(self, group_name):
        if self.group_exists(group_name):
            print(f"{group_name} exists")
        else:
            json_dict = {'computer_group': {'name': group_name, 'is_smart': 'false', 'site': {'id': '-1', 'name': 'None'}, 'criteria': {'size': '0'}, 'computers': {'size': '0'}}}
            self.jamf_api.post("computergroups/id/0", json_dict)
            
class ExemptionPayloadDict(generate_guidance.PayloadDict):
    pass

class ExceptionPreferences:
    pref_domain = "org.mscp.exemptions"

    def __init__(self, file_path=""):
        self._file_path = file_path
    
    @classmethod
    def writeBaselineLocation(cls, location):
        write_plist = subprocess.run(['defaults', 'write', cls.pref_domain, 'baseline_location', location])

    @classmethod
    def readBaselineLocation(cls):
        defaults_read = subprocess.run(['defaults', 'read', f'{cls.pref_domain}', 'baseline_location'],
                                       capture_output=True)
        defaults_error = str.strip(defaults_read.stderr.decode('ascii'))
        yaml_location = str.strip(defaults_read.stdout.decode('ascii'))
        return yaml_location, defaults_error
    
    @classmethod
    def write_api_token_trigger(cls, trigger):
        write_token_trigger = subprocess.run(['defaults', 'write', cls.pref_domain, 'token_trigger', trigger])
    
    @classmethod
    def api_token_trigger(cls):
        defaults_read = subprocess.run(['defaults', 'read', f'{cls.pref_domain}', 'token_trigger'],
                                       capture_output=True)
        defaults_error = str.strip(defaults_read.stderr.decode('ascii'))
        token_trigger = str.strip(defaults_read.stdout.decode('ascii'))
        return token_trigger, defaults_error

    def set_file_path(self, path):
        self._file_path = path

def inf_ddict():
    return defaultdict(inf_ddict)

def process_args():
    arg_parser = argparse.ArgumentParser(description="Process the arguments to determine baseline")
    arg_parser.add_argument("-l", "--list", default=None, help="List the available built baselines")
    arg_parser.add_argument("-s", "--split", default=None,
                            help="Split out the profile plists for domains with multiple settings")
    return arg_parser.parse_args()

def home_menu(baseline, jamf_api):
    menu_options = {
        1: f'Test connection to {jamf_api.hostname}',
        2: f'Edit exceptions for {baseline}',
        3: f'Factor configuration preference conflicts for {baseline}',
        4: 'Reset current baseline',
        5: f'{textcolors.BACKBLUE}Exit{textcolors.ENDC}\n',
    }
    os.system('clear')
    print(f"{textcolors.UNDERLINE}Exception Generator for macOS Security Compliance Project{textcolors.ENDC}\n")

    for key in menu_options.keys():
        print(key, '--', menu_options[key])

def gen_non_exempt_profiles(baseline: MSCPBaseline):
    non_unsigned_mobileconfig_output_path = os.path.join(f'{root_folder()}', 'build', baseline.get_baseline_name(), 'exemptions', 'nonexempt_configs', 'mobileconfigs', 'unsigned')
    if not (os.path.isdir(non_unsigned_mobileconfig_output_path)):
        try:
            os.makedirs(non_unsigned_mobileconfig_output_path)
        except OSError:
            print(f"Couldn't create {non_unsigned_mobileconfig_output_path}")

    non_settings_plist_output_path = os.path.join(f'{root_folder()}', 'build', baseline.get_baseline_name(), 'exemptions', 'nonexempt_configs', 'mobileconfigs', 'preferences')
    if not (os.path.isdir(non_settings_plist_output_path)):
        try:
            os.makedirs(non_settings_plist_output_path)
        except OSError:
            print(f"Couldn't create {non_settings_plist_output_path}")

    p_types = {}
    mount_controls = {}

    for domain_dict in baseline.generate_non_exempt_pofiles():
        for p_type, prefs_dict in domain_dict.items():
            # print(p_type)
            if p_type == 'com.apple.systemuiserver':
                for setting_key, setting in prefs_dict['mount-controls'].items():
                    mount_controls[setting_key] = setting
                    payload = {"mount-controls": mount_controls}
                    p_types.setdefault(p_type,[]).append(payload)
            elif p_type == "com.apple.ManagedClient.preferences":
                for p_domain, settings in prefs_dict.items():
                    for key, value in settings.items():
                        payload = (p_domain, key, value)
                        p_types.setdefault(p_type,[]).append(payload)
            else:
                for p_key, p_value in prefs_dict.items():
                    payload = {p_key: p_value}
                    p_types.setdefault(p_type, []).append(payload)
        # pprint.pprint(p_types)
    
    for p_load, p_settings in p_types.items():
        if p_load.startswith("."):
            non_unsigned_mobileconfig_file_path = os.path.join(non_unsigned_mobileconfig_output_path, f"com.apple{p_load}.mobileconfig")
            non_settings_plist_file_path = os.path.join(non_settings_plist_output_path, f"com.apple{p_load}.plist")
        else:
            non_unsigned_mobileconfig_file_path = os.path.join(non_unsigned_mobileconfig_output_path, f"{p_load}.mobileconfig")
            non_settings_plist_file_path = os.path.join(non_settings_plist_output_path,  f"{p_load}.plist")
        pay_id = f"{p_load}.{baseline.get_baseline_name()}"
        created = date.today()
        descript = "Created: {}\nConfiguration non-exempted settings for the {} preference domain.".format(created, p_load)

        org = "macOS Security Compliance Project"
        display_name = f"[{baseline.get_baseline_name()} {p_load} settings"

        profile = ExemptionPayloadDict(identifier=pay_id, uuid=False, removal_allowed=False, organization=org, displayname=display_name, description=descript)
        if p_load == "com.apple.ManagedClient.preferences":
            for item in p_settings:
                profile.addMCXPayload(item, baseline.get_baseline_name())
        # elif (p_load == "com.apple.applicationaccess.new") or (p_load == "com.apple.systempreferences"):
        #     pprint.pprint(p_settings)
        #     profile.addNewPayload(p_load, generate_guidance.concatenate_payload_settings(p_settings), baseline.get_baseline_name())
        else:
            profile.addNewPayload(p_load, p_settings, baseline.get_baseline_name())

        config_file = open(non_unsigned_mobileconfig_file_path, "wb")
        settings_config_file = open(non_settings_plist_file_path, "wb")
        profile.finalizeAndSave(config_file)
        profile.finalizeAndSavePlist(settings_config_file)
        config_file.close()
    
def gen_exempt_profiles(baseline: MSCPBaseline):
    exe_unsigned_mobileconfig_output_path = os.path.join(f'{root_folder()}', 'build', baseline.get_baseline_name(), 'exemptions', 'exempt_configs', 'mobileconfigs', 'unsigned')
    if not (os.path.isdir(exe_unsigned_mobileconfig_output_path)):
        try:
            os.makedirs(exe_unsigned_mobileconfig_output_path)
        except OSError:
            print(f"Couldn't create {exe_unsigned_mobileconfig_output_path}")

    exe_settings_plist_output_path = os.path.join(f'{root_folder()}', 'build', baseline.get_baseline_name(), 'exemptions', 'exempt_configs', 'mobileconfigs', 'preferences')
    if not (os.path.isdir(exe_settings_plist_output_path)):
        try:
            os.makedirs(exe_settings_plist_output_path)
        except OSError:
            print(f"Couldn't create {exe_settings_plist_output_path}")

    pref_conflicts = baseline.pref_conflicts()

    for exemption in pref_conflicts:
        # print(exemption)
        p_types = {}
        mount_controls = {}
        for exemption_id, all_rules in exemption.items():
            # print(all_rules)
            for rule_id, domains in all_rules.items():
                # print(domains)
                for domain_type, all_settings in domains.items():
                    # print(domain_type)
                    if domain_type == 'com.apple.systemuiserver':
                        for setting_key, setting in all_settings['mount-controls'].items():
                            mount_controls[setting_key] = setting
                            payload = {"mount-controls": mount_controls}
                            # p_types.setdefault(domain_type,[]).append(payload)
                    elif domain_type == "com.apple.ManagedClient.preferences":
                        for p_domain, settings in all_settings.items():
                            for key, value in settings.items():
                                payload = (p_domain, key, value)
                                p_types.setdefault(domain_type,[]).append(payload)
                    else:
                        for p_key, p_value in all_settings.items():
                            payload = {p_key: p_value}
                            # print(payload)
                            p_types.setdefault(domain_type, []).append(payload)
            # print(f'{exemption_id} ---- {p_types}')
                for exe_dom, exe_settings in p_types.items():
                    if exe_dom.startswith("."):
                        exe_unsigned_mobileconfig_file_path = os.path.join(exe_unsigned_mobileconfig_output_path, f"{exemption_id}__com.apple{exe_dom}.mobileconfig")
                        exe_settings_plist_file_path = os.path.join(exe_settings_plist_output_path, f"{exemption_id}__com.apple{exe_dom}.plist")
                    else:
                        exe_unsigned_mobileconfig_file_path = os.path.join(exe_unsigned_mobileconfig_output_path, f"{exemption_id}__{exe_dom}.mobileconfig")
                        exe_settings_plist_file_path = os.path.join(exe_settings_plist_output_path,  f"{exemption_id}__{exe_dom}.plist")
                pay_id = f"{exe_dom}_{exemption_id}.{baseline.get_baseline_name()}"
                created = date.today()
                descript = "Created: {}\nConfiguration non-exempted settings for the {} preference domain.".format(created, exe_dom)
                org = "macOS Security Compliance Project"
                display_name = f"[{baseline.get_baseline_name()} {exemption_id}_{exe_dom} settings"

                profile = ExemptionPayloadDict(identifier=pay_id, uuid=False, removal_allowed=False, organization=org, displayname=display_name, description=descript)
                if exe_dom == "com.apple.ManagedClient.preferences":
                    for item in exe_settings:
                        profile.addMCXPayload(item, baseline.get_baseline_name())
                elif (exe_dom == "com.apple.applicationaccess.new") or (exe_dom == "com.apple.systempreferences"):
                    profile.addNewPayload(exe_dom, generate_guidance.concatenate_payload_settings(exe_settings), baseline.get_baseline_name())
                else:
                    profile.addNewPayload(exe_dom, exe_settings, baseline.get_baseline_name())

                config_file = open(exe_unsigned_mobileconfig_file_path, "wb")
                settings_config_file = open(exe_settings_plist_file_path, "wb")
                profile.finalizeAndSave(config_file)
                profile.finalizeAndSavePlist(settings_config_file)
                config_file.close()
                settings_config_file.close()
                if exe_dom == "com.apple.ManagedClient.preferences":
                    for mcx_item in exe_settings:
                        # print(exe_settings)
                        mcx_dom, _, _ = mcx_item
                        try:
                            print(os.path.join(exe_settings_plist_output_path, f'{mcx_dom}.plist'))
                            os.rename(os.path.join(exe_settings_plist_output_path, f'{mcx_dom}.plist'), os.path.join(exe_settings_plist_output_path, f'{exemption_id}__{mcx_dom}.plist'))
                        except OSError:
                            print("File doesn't exist")

def main():
    # Load Jamf API
    
    if not jamf_mod_avail:
        print("Jamf module not available. Follow the instructions for installing and setting up the Jamf module from the python-jamf git:")
        print("https://github.com/univ-of-utah-marriott-library-apple/python-jamf/wiki/Installing")
    else:
        api = jamf.API()
        jamf_connect = JamfConnect(api)

    # args=process_args()
    current_baseline = MSCPBaseline()
    baseline_yaml_location, defaults_error = ExceptionPreferences.readBaselineLocation()

    if defaults_error:
        while True:
            current_baseline.select_baseline()
            return_state, return_value = current_baseline.loadYAML()

            if return_state:

                break
            else:
                print("Error with loading the file. Please select a baseline YAML file.")
    else:
        current_baseline.set_yaml_location(baseline_yaml_location)
        current_baseline.set_baseline_exemption_folder()


    while True:
        home_menu(current_baseline.get_baseline_name(), api)
        number_of_exemptions = len(current_baseline.get_current_exemptions())
        print(f'There are {number_of_exemptions} exemption(s) defined for the current baseline')
        choice = input("Choose an option: ")
        choice = choice.strip()

        if choice == "1":
            if jamf_mod_avail:
                jamf_connect.jamf_setup_menu()
            else:
                os.system('clear')
                print("Jamf module not available. Follow the instructions for installing and setting up the Jamf module from the python-jamf git:")
                print("https://github.com/univ-of-utah-marriott-library-apple/python-jamf/wiki/Installing")
                input("Press enter to continue.....")
        elif choice == "2":
            current_baseline.show_exemptions_list()
            os.system('clear')
        elif choice == "3":
            current_baseline.display_domain_conflicts()
            sel = input('Generate exempt and non-exempt profiles and preferences?(y/n): ')
            if sel == 'y':
                print('\nGenerating profiles for exemptions.....')
                gen_exempt_profiles(current_baseline)
                print('\nGenerating non-exempt profiles......')
                gen_non_exempt_profiles(current_baseline)
                print(f'\nNew profiles can be found in the macos_security/build/exemptions/{current_baseline.get_baseline_name()} folder\n')
                input('Press enter to continue')       
        elif choice == "4":
            current_baseline.select_baseline()
            os.system('clear')
        elif choice == "5":
            break
        elif choice == "6":
            # pref_domain = PrefDomain('com.apple.applicationaccess')
            # exemption = MSCPExemption()
            # exemption.set_yaml_location('/Users/cbg/Documents/Repos/macOS Security Project/Monterey/macos_security/build/exemptions/800-53r5_moderate/ssh.yaml')
            # exemption.loadYAML()
            # print(root_folder())
            # print(exemption.domains_in_exemption())
            # print(file_path)
            # print(parent_dir)
            # print(root_folder())
            # print(rule.get_yaml_stream())
            # rule._baseline = current_baseline
            # pprint.pprint(current_baseline.all_exemption_domains())
            # pprint.pprint(len(pref_domain.exclude_exemption_rules(current_baseline)[pref_domain.domain]))
            # pprint.pprint(pref_domain.exclude_exemption_rules(current_baseline))
            # current_baseline.generate_non_exempt_pofiles()
            # current_baseline.display_domain_conflicts()
            # gen_non_exempt_profiles(current_baseline)
            # print(os.path.join(root_folder(), 'scripts'))
            # newProfile = ExemptionPayloadDict(identifier="theidentifier", uuid=False, removal_allowed=False, organization="ornl", displayname="ThisProfile", description="descript")
            # print(newProfile.data)
            # gen_non_exempt_profiles(current_baseline)
            # pprint.pprint(pref_domain.get_all_settings_for_baseline(current_baseline))
            # pprint.pprint(current_baseline.non_exempted_domain_settings())
            # print(current_baseline.pref_conflicts())
            # current_baseline.get_rule_list()
            # current_baseline.get_pref_domains()
            # current_baseline.generate_non_exempt_pofiles()
            # print(current_baseline.generate_non_exempt_pofiles())
            # gen_exempt_profiles(current_baseline)
            # pprint.pprint(current_baseline.all_exemption_domains())
            input('\nPress enter to continue')
        else:
            print("Invalid selection. Please try again")

if __name__ == "__main__":
    main()
    