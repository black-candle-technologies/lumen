import activityYaml from '../../../../../mock_data/activity.yaml?raw';
import approvalsYaml from '../../../../../mock_data/approvals.yaml?raw';
import auditEventsYaml from '../../../../../mock_data/audit_events.yaml?raw';
import jobsYaml from '../../../../../mock_data/jobs.yaml?raw';
import messagesYaml from '../../../../../mock_data/messages.yaml?raw';
import modelsYaml from '../../../../../mock_data/models.yaml?raw';
import pluginsYaml from '../../../../../mock_data/plugins.yaml?raw';
import runtimeYaml from '../../../../../mock_data/runtime.yaml?raw';
import settingsGroupsYaml from '../../../../../mock_data/settings_groups.yaml?raw';
import { loadYaml } from './yaml';
import type {
	Approval,
	AuditEvent,
	Job,
	Message,
	ModelProvider,
	Plugin,
	RuntimeStatus,
	SettingsGroup
} from './types';

export * from './types';

// expose yaml fixtures as typed mock records
export const runtime = loadYaml<RuntimeStatus>(runtimeYaml);
export const activity = loadYaml<string[]>(activityYaml);
export const jobs = loadYaml<Job[]>(jobsYaml);
export const approvals = loadYaml<Approval[]>(approvalsYaml);
export const auditEvents = loadYaml<AuditEvent[]>(auditEventsYaml);
export const plugins = loadYaml<Plugin[]>(pluginsYaml);
export const models = loadYaml<ModelProvider[]>(modelsYaml);
export const messages = loadYaml<Message[]>(messagesYaml);
export const settingsGroups = loadYaml<SettingsGroup[]>(settingsGroupsYaml);
