#!/usr/bin/python3

import copy
import json
import multiprocessing
import os

import psi.components
import psi.utils

# ATVG plugins.
from psi.avtg.emg import EMG
from psi.avtg.rsg import RSG
from psi.avtg.weaver import Weaver


def before_launch_all_components(context):
    context.mqs['AVTG common prj attrs'] = multiprocessing.Queue()
    context.mqs['verification obj descs'] = multiprocessing.Queue()
    context.mqs['src tree root'] = multiprocessing.Queue()


def after_extract_common_prj_attrs(context):
    context.mqs['AVTG common prj attrs'].put(context.common_prj_attrs)


def after_extract_src_tree_root(context):
    context.mqs['src tree root'].put(context.src_tree_root)


def after_generate_verification_obj_desc(context):
    # We need to copy verification object description since it may be accidently overwritten by LKVOG.
    context.mqs['verification obj descs'].put(copy.deepcopy(context.verification_obj_desc))


def after_generate_all_verification_obj_descs(context):
    context.logger.info('Terminate verification object descriptions message queue')
    context.mqs['verification obj descs'].put(None)


# This function is invoked to collect plugin callbacks.
def _extract_rule_spec_descs(conf, logger):
    logger.info('Extract rule specificaction decriptions')

    # Read rule specification descriprions DB.
    with open(psi.utils.find_file_or_dir(logger, conf['main working directory'], conf['rule specifications DB'])) as fp:
        descs = json.load(fp)

    rule_spec_descs = []

    for rule_spec_id in conf['rule specifications']:
        logger.info('Extract description for rule specification "{0}"'.format(rule_spec_id))

        # Get raw rule specification description.
        if 'rule specifications' not in descs or rule_spec_id not in descs['rule specifications']:
            is_alias_found = False
            for potential_rule_spec_id, potential_rule_spec_desc in descs['rule specifications'].items():
                if 'aliases' in potential_rule_spec_desc:
                    for alias in potential_rule_spec_desc['aliases']:
                        if rule_spec_id == alias:
                            is_alias_found = True
                            logger.debug(
                                'Rule specification "{0}" was found by alias "{1}"'.format(potential_rule_spec_id,
                                                                                           rule_spec_id))
                            # Use true rule specification ID rather than its alias further.
                            rule_spec_id = potential_rule_spec_id
                            break
                if is_alias_found:
                    rule_spec_desc = potential_rule_spec_desc
                    break

            if not is_alias_found:
                raise ValueError(
                    'Specified rule specification "{0}" could not be found in rule specifications DB'.format(
                        rule_spec_id))
        else:
            rule_spec_desc = descs['rule specifications'][rule_spec_id]

        # Get rid of useless information.
        for attr in ('aliases', 'desc'):
            if attr in rule_spec_desc:
                del (rule_spec_desc[attr])

        # Get rule specification template which it is based on.
        if 'template' not in rule_spec_desc:
            raise ValueError(
                'Rule specification "{0}" has not mandatory attribute "template"'.format(rule_spec_id))
        tmpl_id = rule_spec_desc['template']
        # This information won't be used any more.
        del (rule_spec_desc['template'])
        logger.debug('Rule specification "{0}" template is "{1}"'.format(rule_spec_id, tmpl_id))
        if 'templates' not in descs or tmpl_id not in descs['templates']:
            raise ValueError(
                'Template "{0}" specified in rule specification "{0}" could not be found in rule specifications DB'.format(
                    tmpl_id, rule_spec_id))
        tmpl_desc = descs['templates'][tmpl_id]

        # Get raw template plugins.
        if 'plugins' not in tmpl_desc:
            raise ValueError(
                'Template "{0}" has not mandatory attribute "plugins"'.format(tmpl_id))
        # Copy plugin descriptions since we will overwrite them while the same template can be used by different rule
        # specifications
        plugin_descs = copy.deepcopy(tmpl_desc['plugins'])
        for idx, plugin_desc in enumerate(plugin_descs):
            if 'name' not in plugin_desc:
                raise ValueError(
                    'Template "{0}" plugin "{1}" has not mandatory attribute "name"'.format(tmpl_id, idx))
        logger.debug(
            'Template "{0}" plugins are "{1}"'.format(tmpl_id, [plugin_desc['name'] for plugin_desc in plugin_descs]))

        # Add plugin options specific for rule specification.
        rule_spec_plugin_names = []
        for attr in rule_spec_desc:
            # Names of all other attributes are considered as plugin names, values - as corresponding plugin options.
            if attr not in ('aliases', 'desc', 'bug kinds', 'template'):
                plugin_name = attr
                rule_spec_plugin_names.append(plugin_name)
                is_plugin_specified = False

                for plugin_desc in plugin_descs:
                    if plugin_name == plugin_desc['name']:
                        is_plugin_specified = True
                        if 'opts' not in plugin_desc:
                            plugin_desc['opts'] = {}
                        plugin_desc['opts'].update(rule_spec_desc[plugin_name])
                        logger.debug(
                            'Plugin "{0}" options specific for rule specification "{1}" are "{2}"'.format(plugin_name,
                                                                                                          rule_spec_id,
                                                                                                          rule_spec_desc[
                                                                                                              plugin_name]))
                        break

                if not is_plugin_specified:
                    raise ValueError(
                        'Rule specification "{0}" plugin "{1}" is not specified in template "{2}"'.format(
                            rule_spec_id, plugin_name, tmpl_id))
        # We don't need to keep plugin options specific for rule specification in such the form any more.
        for plugin_name in rule_spec_plugin_names:
            del (rule_spec_desc[plugin_name])
        rule_spec_desc['plugins'] = plugin_descs

        rule_spec_descs.append({'id': rule_spec_id, 'plugins': plugin_descs, 'bug kinds': rule_spec_desc['bug kinds']})

    return rule_spec_descs


_rule_spec_descs = None
_plugins = (EMG, RSG, Weaver)


def get_subcomponent_callbacks(conf, logger):
    logger.info('Get AVTG plugin callbacks')

    global _rule_spec_descs
    _rule_spec_descs = _extract_rule_spec_descs(conf, logger)

    plugins = []

    # Find appropriate classes for plugins if so.
    for rule_spec_desc in _rule_spec_descs:
        for plugin_desc in rule_spec_desc['plugins']:
            plugin_found = False
            for plugin in _plugins:
                if plugin_desc['name'] == plugin.__name__:
                    plugin_found = True
                    # Remember found class to create its instance during main operation.
                    plugin_desc['plugin'] = plugin
                    if plugin not in plugins:
                        plugins.append(plugin)
                    break
            if not plugin_found:
                raise NotImplementedError('Plugin {0} is not supported'.format(plugin_desc['name']))

    return psi.utils.get_component_callbacks(logger, plugins, conf)


class AVTG(psi.components.Component):
    def generate_abstract_verification_tasks(self):
        self.common_prj_attrs = {}
        self.plugins_work_dir = None
        self.extract_common_prj_attrs()
        psi.utils.report(self.logger,
                         'attrs',
                         {'id': self.name,
                          'attrs': self.common_prj_attrs},
                         self.mqs['report files'],
                         self.conf['main working directory'])
        self.extract_src_tree_root()
        self.rule_spec_descs = _rule_spec_descs
        psi.utils.invoke_callbacks(self.generate_all_abstract_verification_task_descs)

    main = generate_abstract_verification_tasks

    def extract_common_prj_attrs(self):
        self.logger.info('Extract common project atributes')

        self.common_prj_attrs = self.mqs['AVTG common prj attrs'].get()

        self.mqs['AVTG common prj attrs'].close()

    def extract_src_tree_root(self):
        self.logger.info('Extract source tree root')

        self.conf['source tree root'] = self.mqs['src tree root'].get()

        self.mqs['src tree root'].close()

        self.logger.debug('Source tree root is "{0}"'.format(self.conf['source tree root']))

    def generate_all_abstract_verification_task_descs(self):
        self.logger.info('Generate all abstract verification task decriptions')

        # TODO: use different MQs for different workers when abstract verification task descriptions will be generated
        # in parallel (see below).
        self.mqs.update({'abstract task description': multiprocessing.Queue()})

        while True:
            verification_obj_desc = self.mqs['verification obj descs'].get()

            if verification_obj_desc is None:
                self.logger.debug('Verification object descriptions message queue was terminated')
                self.mqs['verification obj descs'].close()
                break

            # TODO: specification requires to do this in parallel...
            for rule_spec_desc in self.rule_spec_descs:
                self.generate_abstact_verification_task_desc(verification_obj_desc, rule_spec_desc)

    def generate_abstact_verification_task_desc(self, verification_obj_desc, rule_spec_desc):
        # TODO: print progress: n + 1/N, where n/N is the number of already generated/all to be generated verification tasks.
        self.logger.info(
            'Generate abstract verification task description for {0}'.format(
                'verification object "{0}" and rule specification "{1}"'.format(
                    verification_obj_desc['id'], rule_spec_desc['id'])))

        self.plugins_work_dir = os.path.relpath(
            os.path.join(self.conf['main working directory'], '{0}.task'.format(verification_obj_desc['id']),
                         rule_spec_desc['id']))
        os.makedirs(self.plugins_work_dir)
        self.logger.debug('Plugins working directory is "{0}"'.format(self.plugins_work_dir))

        # Initial abstract verification task looks like corresponding verification object.
        initial_abstract_task_desc = copy.deepcopy(verification_obj_desc)
        initial_abstract_task_desc['id'] = '{0}/{1}'.format(verification_obj_desc['id'], rule_spec_desc['id'])
        for grp in initial_abstract_task_desc['grps']:
            grp['cc extra full desc files'] = [{'cc full desc file': cc_full_desc_file} for cc_full_desc_file in
                                               grp['cc full desc files']]
            del(grp['cc full desc files'])
        self.mqs['abstract task description'].put(initial_abstract_task_desc)
        if self.conf['debug']:
            initial_abstract_task_desc_file = os.path.join(self.plugins_work_dir, 'abstract task.json')
            self.logger.debug('Create initial abstract verification task description file "{0}"'.format(initial_abstract_task_desc_file))
            with open(initial_abstract_task_desc_file, 'w') as fp:
                json.dump(initial_abstract_task_desc, fp, sort_keys=True, indent=4)

        # Invoke all plugins one by one.
        for plugin_desc in rule_spec_desc['plugins']:
            self.logger.info('Launch plugin {0}'.format(plugin_desc['name']))

            # Get plugin configuration on the basis of common configuration, plugin options specific for rule
            # specification and information on rule specification itself.
            plugin_conf = copy.deepcopy(self.conf)
            if 'opts' in plugin_desc:
                plugin_conf.update(plugin_desc['opts'])
            plugin_conf.update({'rule spec id': rule_spec_desc['id'], 'bug kinds': rule_spec_desc['bug kinds']})

            p = plugin_desc['plugin'](plugin_conf, self.logger, self.name, self.callbacks, self.mqs,
                                      '{0}/{1}/{2}'.format(verification_obj_desc['id'], rule_spec_desc['id'],
                                                           plugin_desc['name']),
                                      os.path.join(self.plugins_work_dir, plugin_desc['name'].lower()),
                                      [{'verification object': verification_obj_desc['id']},
                                       {'rule specification': rule_spec_desc['id']}], True, True)

            # Failures in plugins aren't treated as the critical ones. We just warn and proceed to other
            # verification objects or/and rule specifications.
            try:
                p.start()
                p.join()
            except psi.components.ComponentError:
                break

            # Plugin working directory is created just if plugin starts successfully (above). So we can't dump
            # anything before.
            if self.conf['debug']:
                plugin_conf_file = os.path.join(self.plugins_work_dir, plugin_desc['name'].lower(), 'conf.json')
                self.logger.debug('Create configuration file "{0}"'.format(plugin_conf_file))
                with open(plugin_conf_file, 'w') as fp:
                    json.dump(plugin_conf, fp, sort_keys=True, indent=4)

                cur_abstract_task_desc_file = os.path.join(self.plugins_work_dir, plugin_desc['name'].lower(), 'abstract task.json')
                self.logger.debug('Create current abstract verification task description file "{0}"'.format(cur_abstract_task_desc_file))
                # Temporarily get current abstract verification task description.
                cur_abstract_task_desc = self.mqs['abstract task description'].get()
                with open(cur_abstract_task_desc_file, 'w') as fp:
                    json.dump(cur_abstract_task_desc, fp, sort_keys=True, indent=4)
                # Return current abstract verification task description back.
                self.mqs['abstract task description'].put(cur_abstract_task_desc)
