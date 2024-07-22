import {
  AttributeValue,
  DynamoDBClient,
  QueryCommand,
  TransactWriteItemsCommand,
  TransactWriteItemsCommandInput,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb'
import {
  CustomerProjectDeleteParamsType,
  CustomerProjectUpdateParamsType,
  ProjectReadParamsType,
  TaskCreateReadParamsType,
  TaskReadParamsType,
  TaskUpdateParamsType,
} from '@src/core/Task/model/task.model'
import { TaskRepositoryInterface } from '@src/core/Task/repository/TaskRepositoryInterface'
import { InvalidCharacterError } from '@src/core/customExceptions/InvalidCharacterError'
import { getTableName } from '@src/core/db/TableName'
import { TimeEntryRowType } from '@src/core/TimeEntry/model/timeEntry.model'
import { TaskError } from '@src/core/customExceptions/TaskError'

export class TaskRepository implements TaskRepositoryInterface {
  constructor(private dynamoDBClient: DynamoDBClient) {}

  async getCustomers(company: string): Promise<string[]> {
    const command = new QueryCommand({
      TableName: getTableName('Task'),
      KeyConditionExpression: 'company = :company',
      FilterExpression: 'inactive = :inactive',
      ExpressionAttributeValues: {
        ':company': { S: company },
        ':inactive': { BOOL: false },
      },
    })
    const result = await this.dynamoDBClient.send(command)
    return Array.from(
      new Set(
        result.Items?.map(
          (item) => item.customerProject?.S?.split('#')[0] ?? '',
        ) ?? [],
      ),
    ).sort()
  }

  async getProjects(params: ProjectReadParamsType): Promise<string[]> {
    const command = new QueryCommand({
      TableName: getTableName('Task'),
      KeyConditionExpression:
        'company = :company and begins_with(customerProject, :customer)',
      FilterExpression: 'inactive = :inactive',
      ExpressionAttributeValues: {
        ':company': { S: params.company },
        ':customer': { S: params.customer },
        ':inactive': { BOOL: false },
      },
    })
    const result = await this.dynamoDBClient.send(command)
    return (
      result.Items?.map((item) => {
        if (
          item.customerProject?.S?.split('#')[1] &&
          item.customerProject?.S?.split('#')[0] === params.customer
        ) {
          return item.customerProject?.S?.split('#')[1]
        } else {
          return ''
        }
      }).sort() ?? []
    ).filter((item) => item != '')
  }

  async getTasks(params: TaskReadParamsType): Promise<string[]> {
    const command = new QueryCommand({
      TableName: getTableName('Task'),
      KeyConditionExpression:
        'company = :company and customerProject = :customerProject',
      FilterExpression: 'inactive = :inactive',
      ExpressionAttributeValues: {
        ':company': { S: params.company },
        ':customerProject': { S: `${params.customer}#${params.project}` },
        ':inactive': { BOOL: false },
      },
    })
    const result = await this.dynamoDBClient.send(command)
    return (
      result.Items?.map((item) => item.tasks?.SS ?? [])
        .flat()
        .sort() ?? []
    )
  }

  async getTasksWithProjectType(
    params: TaskReadParamsType,
  ): Promise<{ tasks: string[]; projectType: string }> {
    const command = new QueryCommand({
      TableName: getTableName('Task'),
      KeyConditionExpression:
        'company = :company and customerProject = :customerProject',
      FilterExpression: 'inactive = :inactive',
      ExpressionAttributeValues: {
        ':company': { S: params.company },
        ':customerProject': { S: `${params.customer}#${params.project}` },
        ':inactive': { BOOL: false },
      },
    })
    const result = await this.dynamoDBClient.send(command)

    if (result.Items) {
      const tasks =
        result.Items.map((item) => item.tasks?.SS ?? [])
          .flat()
          .sort() ?? []
      const projectType = result.Items[0].projectType?.S ?? ''
      return {
        tasks,
        projectType,
      }
    }

    return {
      tasks: [],
      projectType: '', //TODO
    }
  }

  async createTask(params: TaskCreateReadParamsType): Promise<void> {
    const company = params.company
    const project = params.project
    const projectType = params.projectType
    const customer = params.customer
    const task = params.task

    if (customer.includes('#') || project.includes('#')) {
      throw new InvalidCharacterError(
        '# is not a valid character for customer or project',
      )
    }

    if (!params.projectType) {
      throw new TaskError('Project type missing')
    }

    const customerProject = `${customer}#${project}`
    const updateParams = {
      TableName: getTableName('Task'),
      Key: {
        customerProject: { S: customerProject },
        company: { S: company },
      },
      UpdateExpression:
        'SET projectType = :projectType, inactive = :inactive ADD tasks :task',
      ExpressionAttributeValues: {
        ':task': {
          SS: [task],
        },
        ':projectType': { S: projectType },
        ':inactive': { BOOL: false },
      },
    }
    await this.dynamoDBClient.send(new UpdateItemCommand(updateParams))
  }

  async updateCustomerProject(
    params: CustomerProjectUpdateParamsType,
  ): Promise<void> {
    const company = params.company
    const project = params.project
    const customer = params.customer

    let newValue
    let existingCustomerProject
    const oldCustomerProject = `${customer}#${project}`
    let newCustomerProject

    if (params.newCustomer && params.newProject) {
      throw new TaskError('New customer OR new Project must be valorized')
    }
    if (params.newCustomer) {
      newValue = params.newCustomer
      existingCustomerProject = await this.getTasks({
        company,
        project,
        customer: newValue,
      })
      newCustomerProject = `${newValue}#${project}`
    } else if (params.newProject) {
      newValue = params.newProject
      existingCustomerProject = await this.getTasks({
        company,
        project: newValue,
        customer,
      })
      newCustomerProject = `${customer}#${newValue}`
    } else {
      throw new TaskError('New customer OR new Project must be valorized')
    }

    if (newValue.includes('#')) {
      throw new InvalidCharacterError(
        '# is not a valid character for customer or project',
      )
    }

    if (existingCustomerProject.length > 0) {
      //ADD check
      throw new TaskError('Customer project already exists')
    }

    const command = new QueryCommand({
      TableName: getTableName('TimeEntry'),
      IndexName: 'companyIndex',
      KeyConditionExpression: 'company = :company',
      ExpressionAttributeValues: {
        ':company': { S: params.company },
      },
    })
    const result = await this.dynamoDBClient.send(command)
    const timeEntries =
      result.Items?.map((item) => {
        return this.getTimeEntry(item)
      }).flat() ?? []

    const projectAlreadyAssigned = timeEntries.some(
      (entry) =>
        entry.customer === params.customer && entry.project === params.project,
    )
    if (projectAlreadyAssigned) {
      throw new TaskError('Customer project already assigned')
    }

    const oldTasks = await this.getTasksWithProjectType({
      company,
      project,
      customer,
    })

    const input: TransactWriteItemsCommandInput = {
      TransactItems: [
        {
          Delete: {
            Key: {
              company: { S: params.company },
              customerProject: { S: oldCustomerProject },
            },
            TableName: getTableName('Task'),
          },
        },
        {
          Update: {
            Key: {
              company: { S: params.company },
              customerProject: { S: newCustomerProject },
            },
            TableName: getTableName('Task'),
            UpdateExpression:
              'SET #tasks = :tasks, #projectType = :projectType, #inactive = :inactive',
            ExpressionAttributeNames: {
              '#tasks': 'tasks',
              '#projectType': 'projectType',
              '#inactive': 'inactive',
            },
            ExpressionAttributeValues: {
              ':tasks': {
                SS: oldTasks.tasks,
              },
              ':projectType': {
                S: oldTasks.projectType,
              },
              ':inactive': {
                BOOL: false,
              },
            },
          },
        },
      ],
    }

    const transactCommand = new TransactWriteItemsCommand(input)
    await this.dynamoDBClient.send(transactCommand)
  }

  async updateTask(params: TaskUpdateParamsType): Promise<void> {
    const company = params.company
    const project = params.project
    const customer = params.customer

    const customerProject = `${customer}#${project}`

    if (!params.newTask) {
      throw new TaskError('New task must be valorized')
    }

    const command = new QueryCommand({
      TableName: getTableName('TimeEntry'),
      IndexName: 'companyIndex',
      KeyConditionExpression: 'company = :company',
      ExpressionAttributeValues: {
        ':company': { S: params.company },
      },
    })
    const result = await this.dynamoDBClient.send(command)
    const timeEntries =
      result.Items?.map((item) => {
        return this.getTimeEntry(item)
      }).flat() ?? []

    const projectAlreadyAssigned = timeEntries.some(
      (entry) =>
        entry.customer === params.customer &&
        entry.project === params.project &&
        entry.task.includes(params.task),
    )
    if (projectAlreadyAssigned) {
      throw new TaskError('Task already assigned')
    }

    const oldTasksWithProjectType = await this.getTasksWithProjectType({
      company,
      project,
      customer,
    })
    const oldTasks = oldTasksWithProjectType.tasks

    if (oldTasks.includes(params.newTask)) {
      throw new TaskError('Task already exists')
    }

    const newTasks = oldTasks.filter((task) => task !== params.task)
    newTasks.push(params.newTask)

    const updateParams = {
      TableName: getTableName('Task'),
      Key: {
        customerProject: { S: customerProject },
        company: { S: company },
      },
      UpdateExpression: 'SET tasks = :task',
      ExpressionAttributeValues: {
        ':task': {
          SS: newTasks,
        },
      },
    }

    await this.dynamoDBClient.send(new UpdateItemCommand(updateParams))
  }

  async deleteCustomerProject(
    params: CustomerProjectDeleteParamsType,
  ): Promise<void> {
    const company = params.company
    const project = params.project
    const customer = params.customer
    const inactive = params.inactive || true

    const customerProject = `${customer}#${project}`

    const updateParams = {
      TableName: getTableName('Task'),
      Key: {
        customerProject: { S: customerProject },
        company: { S: company },
      },
      UpdateExpression: 'SET inactive = :inactive',
      ExpressionAttributeValues: {
        ':inactive': {
          BOOL: inactive,
        },
      },
    }
    await this.dynamoDBClient.send(new UpdateItemCommand(updateParams))
  }

  async populateTasks(): Promise<void> {
    const company = 'it'
    const projectType = 'billable'

    const input = [
      {
        customer: 'Abilio S.p.a',
        project:
          'CLT-0410/24 - CL - Abilio - Rinnovo contrattuale Q4 2023 Progetto Abilio Spa',
        task: 'ITERAZIONE 133 parte 2 (dal 01 gennaio al 05 gennaio)',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 134 - 8-12 gennaio',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 135 - 15-19 gennaio',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 136 - 22-26 gennaio',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 137 - 29 gennaio - 2 febbraio',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 138 - 5-9 febbraio',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 139 - 12-16 febbraio',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 140 - 19-23 febbraio',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 141 - 26 febbraio - 1 marzo',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 142 - 4-8 marzo',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 143 - 11-15 marzo',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 144 - 18-22 marzo',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0477/24 - CL - Abilio Rinnovo contrattuale Sor q1 2024',
        task: 'ITERAZIONE 145 - 25-29 marzo',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0478/24 - CL - Abilio - Sviluppo T&M dic 23',
        task: 'sviluppo',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0566/24 - CL - Abilio - Sviluppo T&M su Quimmo Aprile 24',
        task: 'sviluppo',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 146 - 1-5 aprile',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 147: 8/04 - 12/04',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 148: 15/04 - 19/04',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 149: 22/04 - 26/04',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 150: 29/04 - 04/05',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 151: 6/05 - 10/05',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 152: 13/05 - 17/05',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 153: 20/05 - 24/05',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 154: 27/05 - 31/05',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 155: 03/06 - 07/06',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 156: 10/06 - 14/06',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 157: 17/06 - 21/06',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0571-24 - CL - Abilio - Rinnovo contrattuale Son Q2 2024',
        task: 'ITERAZIONE 158: 24/06 - 28/06',
      },
      {
        customer: 'Abilio S.p.a',
        project:
          'CLT-0614-24 - CL - Abilio - Rinnovo contrattuale Q3 2024 Progetto Abilio Spa',
        task: 'ITERAZIONE 158: 24/06 - 28/06',
      },
      {
        customer: 'Abilio S.p.a',
        project:
          'CLT-0614-24 - CL - Abilio - Rinnovo contrattuale Q3 2024 Progetto Abilio Spa',
        task: 'ITERAZIONE 159: 01 - 05 luglio',
      },
      {
        customer: 'Abilio S.p.a',
        project:
          'CLT-0614-24 - CL - Abilio - Rinnovo contrattuale Q3 2024 Progetto Abilio Spa',
        task: 'ITERAZIONE 160: 08 - 12 luglio',
      },
      {
        customer: 'Abilio S.p.a',
        project:
          'CLT-0614-24 - CL - Abilio - Rinnovo contrattuale Q3 2024 Progetto Abilio Spa',
        task: 'ITERAZIONE 161: 15 - 19 luglio',
      },
      {
        customer: 'Abilio S.p.a',
        project: 'CLT-0615/24 - CL - Abilio - Sviluppo T&M su Quimmo Giugno 24',
        task: 'sviluppo',
      },
      {
        customer: 'Acantho',
        project: 'CLT-0001/23 - CL - Acantho - Managed Service on AWS',
        task: 'MS Acantho AREA-1',
      },
      {
        customer: 'Acantho',
        project: 'CLT-0001/23 - CL - Acantho - Managed Service on AWS',
        task: 'MS Acantho INCIDENT',
      },
      {
        customer: 'Acantho',
        project:
          'CLT-0174/23 - CL - Amazon - Migrazione Liferay per Hera Fase 3',
        task: 'Build:2G',
      },
      {
        customer: 'Acantho',
        project: 'CLT-0377/24 - CL - Acantho - MS BANDO 2024-25',
        task: 'MS - Area 1',
      },
      {
        customer: 'Acantho',
        project: 'CLT-0377/24 - CL - Acantho - MS BANDO 2024-25',
        task: 'MS - Incident',
      },
      {
        customer: 'Acantho',
        project:
          'CLT-0501/24 - CL - Amazon - Migrazione Liferay per HERA fase 4',
        task: '(Without task)',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0105/22 - CL - Alperia - Offerta Managed Service',
        task: 'MS Alperia AREA-1',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0105/22 - CL - Alperia - Offerta Managed Service',
        task: 'MS Alperia INCIDENT',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0219/23 - CL - Alperia - MS RINNOVO FY24',
        task: 'MS Alperia AREA-1',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0219/23 - CL - Alperia - MS RINNOVO FY24',
        task: 'MS Alperia INCIDENT',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0339/23 - CL - Alperia - Rinnovo ENG Cloud',
        task: 'Attività di Engineering',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0339/23 - CL - Alperia - Rinnovo ENG Cloud',
        task: 'Hydrosim',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0339/23 - CL - Alperia - Rinnovo ENG Cloud',
        task: 'Lava',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0339/23 - CL - Alperia - Rinnovo ENG Cloud',
        task: 'MS Improvements',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0339/23 - CL - Alperia - Rinnovo ENG Cloud',
        task: 'Portale unico',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0339/23 - CL - Alperia - Rinnovo ENG Cloud',
        task: 'Security',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0339/23 - CL - Alperia - Rinnovo ENG Cloud',
        task: 'Splunk',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0339/23 - CL - Alperia - Rinnovo ENG Cloud',
        task: 'Theseus',
      },
      {
        customer: 'Alperia',
        project: 'CLT-0339/23 - CL - Alperia - Rinnovo ENG Cloud',
        task: 'Webticket',
      },
      {
        customer: 'Amnesty',
        project: 'CLT-0425/24 - CL - Amnesty - MS 2024',
        task: 'MS Amnesty Area - 1',
      },
      {
        customer: 'Amnesty',
        project: 'CLT-0425/24 - CL - Amnesty - MS 2024',
        task: 'MS Amnesty Area - 2',
      },
      {
        customer: 'Amnesty',
        project: 'CLT-0425/24 - CL - Amnesty - MS 2024',
        task: 'MS Amnesty Area - Incident',
      },
      {
        customer: 'Banca Mediolanum',
        project: 'CLT-0232-23 - CL - BMED - Application Maintenance',
        task: 'Analisi/Stima',
      },
      {
        customer: 'Banca Mediolanum',
        project: 'CLT-0232-23 - CL - BMED - Application Maintenance',
        task: 'SAL',
      },
      {
        customer: 'Banca Mediolanum',
        project: 'CLT-0232-23 - CL - BMED - Application Maintenance',
        task: 'Sviluppo',
      },
      {
        customer: 'Banca Mediolanum',
        project:
          'CLT-0457/24 - CL - BMED - progetto multicanalità - upgrade vue3',
        task: 'sviluppo',
      },
      {
        customer: 'Banca Mediolanum',
        project: 'CLT-0468/24 - BMED - Miglioramento Continuo 2024',
        task: 'Junior',
      },
      {
        customer: 'Banca Mediolanum',
        project: 'CLT-0468/24 - BMED - Miglioramento Continuo 2024',
        task: 'Senior',
      },
      {
        customer: 'BeCloud Solutions',
        project: 'CLT-0155/23 - CL - BeCloud - MS for 2023',
        task: 'MS BeCloud Area - 1',
      },
      {
        customer: 'BeCloud Solutions',
        project: 'CLT-0155/23 - CL - BeCloud - MS for 2023',
        task: 'MS BeCloud Incident',
      },
      {
        customer: 'BeCloud Solutions',
        project: 'CLT-0505/24 - CL - BeCloud - MS Renew 2024',
        task: 'provvisorio',
      },
      {
        customer: 'Benelli Armi S.p.a.',
        project: 'CLT-0552-24 - CL - Manutenzione software Benelli Caddy',
        task: 'Manutenzione',
      },
      {
        customer: 'Carimali S.p.a.',
        project:
          'CLT-0140/23 - CL - Carimali - MS for Infra and application 2023',
        task: 'MS Carimali',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0368/24 - CL - Carimali - Pacchetto T/M Sviluppo SW',
        task: 'Sviluppo',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0391/24 - CL - Carimali - Affiancamento e formazione',
        task: 'affiancamento e formazione',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'IT 3: 1-7 feb',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'IT4: 08-14 feb',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'IT5: 15-16 feb',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'IT6: 19-21 feb',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'IT7: 22-23 feb',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'IT8: 26-28 feb',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 10: 7 mar -- 13 mar',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 11: 14 mar - 15 mar',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 12: 18 mar - 20 mar',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 13: 21 mar - 22 mar',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 14: 25 mar - 27 mar',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 15: 28 mar - 29 mar',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 16: 02 apr- 05 apr',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 17: 08 apr - 10 apr',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 18: 11 apr - 12 apr',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 19: 15 apr - 17 apr',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 1: 17 gennaio --24 gennaio',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 20: 18 apr - 19 apr',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 21: 21 apr - 26 apr',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 22 (29/4/24-30/4/24)',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 23 (2/5/24-6/5/24)',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 24 (7/5/24-10/5/24)',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 25 (13/5/24-14/5/24)',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 26 15/5/24 17/5/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 27 20/5/24 22/5/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 28 23/5/2424/5/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 29 (27/5/24-30/5/24)',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 2: 25 gennaio --31 gennaio',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 30 31/5/24 5/6/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0392/24 - CL - Carimali - SOR Supporto, Sviluppo e Cloud',
        task: 'ITERAZIONE 9: 5 mar -- 6 mar',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 10',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 11',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 12',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 1: 6/6/24 10/6/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 2: 11/6/24 13/6/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 3: 14/6/24 17/6/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 4: 18/6/24 20/6/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 5: 21/6/24 24/6/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 6: 25/6/24 27/6/24',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 7',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 8',
      },
      {
        customer: 'Carimali S.p.a.',
        project: 'CLT-0594/24 - Carimali - SOR Sviluppo SW&Cloud H22024',
        task: 'ITERAZIONE 9',
      },
      {
        customer: 'Cartsan srl',
        project: 'CLT-0299/23 - CL - Cartsan - Supporto e consulenza AWS',
        task: 'Cloud',
      },
      {
        customer: 'Cartsan srl',
        project:
          'CLT-0622/24 - Cartsan - Supporto e consulenza AWS (Giugno 24)',
        task: 'cloud',
      },
      {
        customer: 'Cerved',
        project: 'CLT-0011/22 - CL - Cerved - MS PSD2',
        task: 'MS - Area 1',
      },
      {
        customer: 'Cerved',
        project: 'CLT-0011/22 - CL - Cerved - MS PSD2',
        task: 'MS - Audit',
      },
      {
        customer: 'Cerved',
        project: 'CLT-0011/22 - CL - Cerved - MS PSD2',
        task: 'MS - Incident',
      },
      {
        customer: 'Cerved',
        project: 'CLT-0233/23 - CL - CERVED - MS RINNOVO 2023 (ex 057)',
        task: 'MS Cerved AREA-1',
      },
      {
        customer: 'Cerved',
        project: 'CLT-0233/23 - CL - CERVED - MS RINNOVO 2023 (ex 057)',
        task: 'MS Cerved INCIDENT',
      },
      {
        customer: 'Cerved',
        project: 'CLT-0508/24 - CL - Cerved - MS 2024 ex 0233',
        task: 'MS Cerved AREA1',
      },
      {
        customer: 'Cerved',
        project: 'CLT-0508/24 - CL - Cerved - MS 2024 ex 0233',
        task: 'MS Cerved AREA2',
      },
      {
        customer: 'Cerved',
        project: 'CLT-0508/24 - CL - Cerved - MS 2024 ex 0233',
        task: 'MS Cerved Incident',
      },
      {
        customer: 'Cerved SAS',
        project: 'CLT-0079/22 - CL - Cerved SAS - MS on AWS',
        task: 'MS Cerved SAS AREA-1',
      },
      {
        customer: 'Cerved SAS',
        project: 'CLT-0079/22 - CL - Cerved SAS - MS on AWS',
        task: 'MS Cerved SAS AREA-2',
      },
      {
        customer: 'Cerved SAS',
        project: 'CLT-0079/22 - CL - Cerved SAS - MS on AWS',
        task: 'MS Cerved SAS INCIDENT',
      },
      {
        customer: 'Chiesi',
        project: 'CLT-0344/24 - CL - Chiesi - Cloud ENG package',
        task: 'engineering',
      },
      {
        customer: 'Chiesi',
        project: 'CLT-0353/24 - CL - Chiesi - MS Shared Account 2024',
        task: 'Area-1',
      },
      {
        customer: 'Chiesi',
        project: 'CLT-0353/24 - CL - Chiesi - MS Shared Account 2024',
        task: 'Area-2',
      },
      {
        customer: 'Chiesi',
        project: 'CLT-0353/24 - CL - Chiesi - MS Shared Account 2024',
        task: 'Incident',
      },
      {
        customer: 'Chiesi',
        project: 'CLT-0549/24 - Chiesi - Enginnering Cloud T&M 2024',
        task: 'engineering',
      },
      {
        customer: 'Claranet UK',
        project: 'CLT-0409/24 - IC - Mediq per Claranet UK - Progetto',
        task: '(Without task)',
      },
      {
        customer: 'Claranet UK',
        project: 'CLT-0511/24 - IC - Claranet UK - Discovery cliente UK WSP',
        task: 'sviluppo',
      },
      {
        customer: 'Daldoss Elevetronic Spa',
        project: 'CLT -0551/24 - CL - Daldoss Pacchetto giornate T&M 2024',
        task: 'cloud',
      },
      {
        customer: 'Daldoss Elevetronic Spa',
        project: 'CLT -0551/24 - CL - Daldoss Pacchetto giornate T&M 2024',
        task: 'sviluppo',
      },
      {
        customer: 'Daldoss Elevetronic Spa',
        project:
          'CLT-0400/24 - CL - Daldoss - Sviluppo software e supporto applicativo piattaforma gestione ordini (CRM) ex0278/23',
        task: 'Iterazione 11 - 11/01 - 25/01',
      },
      {
        customer: 'Daldoss Elevetronic Spa',
        project:
          'CLT-0400/24 - CL - Daldoss - Sviluppo software e supporto applicativo piattaforma gestione ordini (CRM) ex0278/23',
        task: 'Iterazione 12 - 26/01 - 06/02',
      },
      {
        customer: 'Daldoss Elevetronic Spa',
        project:
          'CLT-0400/24 - CL - Daldoss - Sviluppo software e supporto applicativo piattaforma gestione ordini (CRM) ex0278/23',
        task: 'Iterazione 13 - 09/02 - 16/02',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 01 - 09 dal 05/12/2023 al 16/04/2024',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 10 : 17/04 - 23/04',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 11 : 24/04 - 07/05',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 12 : 08/05 - 14/05',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 13 : 15/05 - 21/05',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 14 : 22/05 - 28/05',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 15 : 29/05 - 04/06',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 16 : 05/06 - 11/06',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 17 : 12/06 - 19/06',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 18 : 20/06 - 25/06',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 19 : 26/06 - 02/07',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 20 : 03/07 - 09/07',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 21 : 10/07 - 16/07',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'iterazione 22 : 17/07 - 23/07',
      },
      {
        customer: 'Dipendesse da me Srl',
        project:
          'CLT-0546-24 -CL- Sviluppo software Dipendesse da Me - Scheda Offerta',
        task: 'Iterazione 23 : 24/07 - 30/07',
      },
      {
        customer: 'Doit S.r.l.',
        project: 'CLT-0509/24 - CL - Doit - Rinnovo 2024',
        task: 'Cloud',
      },
      {
        customer: 'Doit S.r.l.',
        project: 'CLT-550-24 - CL - Doit - Sviluppo 2.5 fte 2024',
        task: 'sviluppo',
      },
      {
        customer: 'Doit S.r.l.',
        project: 'CLT-550-24 - CL - Doit - Sviluppo 2.5 fte 2024',
        task: 'sviluppo lead',
      },
      {
        customer: 'Ducati',
        project: 'CLT-0064/23 - CL - Ducati - Rinnovo Managed Service AWS',
        task: 'MS Ducati Area - 1',
      },
      {
        customer: 'Ducati',
        project: 'CLT-0064/23 - CL - Ducati - Rinnovo Managed Service AWS',
        task: 'MS Ducati Incident',
      },
      {
        customer: 'Ducati',
        project:
          'CLT-0395/24 - CL - Ducati - Cloud security e infrastruttura Cloud',
        task: 'progettazione Scrambler 2.0',
      },
      {
        customer: 'Ducati',
        project:
          'CLT-0395/24 - CL - Ducati - Cloud security e infrastruttura Cloud',
        task: 'security',
      },
      {
        customer: 'Ducati',
        project: 'CLT-0449/24 - CL - Ducati - MS 2024 e package security',
        task: 'Area 2',
      },
      {
        customer: 'Ducati',
        project: 'CLT-0449/24 - CL - Ducati - MS 2024 e package security',
        task: 'MS Ducati Area - 1',
      },
      {
        customer: 'Ducati',
        project: 'CLT-0449/24 - CL - Ducati - MS 2024 e package security',
        task: 'MS Ducati Area - Incident',
      },
      {
        customer: 'Ducati',
        project: 'CLT-0544/24 - CL - Ducati - Amazon Workspaces',
        task: 'svluppo',
      },
      {
        customer: 'Ducati',
        project: 'CLT-0633/24 - Ducati - Attività Security',
        task: 'cloud',
      },
      {
        customer: 'Edizioni Centro Studi Erickson SpA',
        project: 'CLT-0530/24 - CL - Erickson - Cloud Assessment',
        task: 'Discovery',
      },
      {
        customer: 'EMOJ S.r.l.',
        project: 'CLT-0647/25 - Emoj - Sviluppo Zoom',
        task: 'sviluppo',
      },
      {
        customer: 'Fme Education Spa',
        project: 'CLT-0593/24 - CL - FME Education T&M Sviluppo SW (MyEDU)',
        task: 'Call & Riunioni',
      },
      {
        customer: 'Fme Education Spa',
        project: 'CLT-0593/24 - CL - FME Education T&M Sviluppo SW (MyEDU)',
        task: 'sviluppo',
      },
      {
        customer: 'Future Fashions s.r.l.',
        project:
          'CLT-0164/23 - FL - Future Fashion - Sviluppo software progetto Automatic 3D',
        task: 'Sviluppo cloud/ux',
      },
      {
        customer: 'Growens',
        project: 'CLT-0217/23 - CL - Growens - CCoE Engineering Growens 2023',
        task: 'CcoE -Attività di Engineering',
      },
      {
        customer: 'Guccio Gucci S.p.A',
        project: 'CLT-0495/24 - CL - Gucci - Sviluppo software 1° semestre 24',
        task: '(Without task)',
      },
      {
        customer: 'Guccio Gucci S.p.A',
        project: 'CLT-0603/24 - CL - Gucci - Sviluppo software 2° semestre 24',
        task: '(Without task)',
      },
      {
        customer: 'Harper Collins Italia S.p.a.',
        project:
          'CLT-0371/24 - CL - HarperCollins - Rinnovo monte ore manutenzione luglio 23',
        task: 'Manutenzione',
      },
      {
        customer: 'Harper Collins Italia S.p.a.',
        project: 'CLT-0538/24 - CL - Harper Collins - Rinnovo monte ore 24',
        task: 'Manutenzione',
      },
      {
        customer: 'Ikonic Srl',
        project: 'CLT-0561-24- CL - Ikonic Srl T&M Cloud Vpn',
        task: 'cloud',
      },
      {
        customer: 'IlMeteo Srl',
        project:
          'CLT-0323/23 - CL - ilMeteo - Sviluppo software e supporto applicativo',
        task: 'sviluppo',
      },
      {
        customer: 'IlSole24ORE',
        project: 'CLT-0135/23 - CL - IlSole24Ore - MS for EspertoRisponde 2023',
        task: 'MS - Area 1',
      },
      {
        customer: 'IlSole24ORE',
        project: 'CLT-0135/23 - CL - IlSole24Ore - MS for EspertoRisponde 2023',
        task: 'MS - Incident',
      },
      {
        customer: 'IlSole24ORE',
        project:
          'CLT-0159/23 - CL - IlSole24Ore - Automatic renew MS for FiscoBOT (CLT-001-21)',
        task: 'MS IlSole24Ore AREA-1',
      },
      {
        customer: 'IlSole24ORE',
        project:
          'CLT-0159/23 - CL - IlSole24Ore - Automatic renew MS for FiscoBOT (CLT-001-21)',
        task: 'MS IlSole24Ore INCIDENT',
      },
      {
        customer: 'IlSole24ORE',
        project: 'CLT-0465/24 - CL - IlSole24Ore - T&M Attività di supporto',
        task: '(Without task)',
      },
      {
        customer: 'IlSole24ORE',
        project: 'CLT-0493/24 - CL - IlSole24Ore - MS FiscoBOT 2024',
        task: 'AREA-1',
      },
      {
        customer: 'IlSole24ORE',
        project: 'CLT-0493/24 - CL - IlSole24Ore - MS FiscoBOT 2024',
        task: 'INCIDENT',
      },
      {
        customer: 'IlSole24ORE',
        project: 'CLT-0503/24 - CL - IlSole24Ore - Supporto Fade Out ER - T&M',
        task: 'Sviluppo',
      },
      {
        customer: 'Infranet',
        project:
          'CLT-0361/24 - CL - Infranet - Sviluppo software e assistenza Luglio-Dicembre 2023',
        task: 'Sviluppo',
      },
      {
        customer: 'Infranet',
        project:
          'CLT-0476/24 - CL - Infranet Sviluppo e Assistenza - Gennaio - Luglio 24',
        task: 'Assistenza',
      },
      {
        customer: 'Infranet',
        project:
          'CLT-0476/24 - CL - Infranet Sviluppo e Assistenza - Gennaio - Luglio 24',
        task: 'Sviluppo',
      },
      {
        customer: 'Infranet',
        project: 'CLT-0597-24 - Infranet - Sviluppo e Assistenza_Lug_Dic2024',
        task: 'assistenza',
      },
      {
        customer: 'Infranet',
        project: 'CLT-0597-24 - Infranet - Sviluppo e Assistenza_Lug_Dic2024',
        task: 'sviluppo',
      },
      {
        customer: 'ISH CONSULTING SRL',
        project:
          'CLT-0481/24 - CL - ISH Consulting - Sviluppo a corpo Alessio Ragni',
        task: 'Discovery',
      },
      {
        customer: 'iSolutions S.r.l.',
        project: 'CLT-0451/24 - CL - iSolution Srl Supporto Cloud ottobre 23',
        task: 'Consulenza AWS',
      },
      {
        customer: 'Kettydo+ Srl',
        project: 'CLT-0168/23 - CL - Kettydo+ - MS for 2023',
        task: 'Area 1',
      },
      {
        customer: 'Kettydo+ Srl',
        project: 'CLT-0168/23 - CL - Kettydo+ - MS for 2023',
        task: 'Area 2',
      },
      {
        customer: 'Kettydo+ Srl',
        project: 'CLT-0168/23 - CL - Kettydo+ - MS for 2023',
        task: 'Incident',
      },
      {
        customer: 'Kettydo+ Srl',
        project: 'CLT-0396/24 - CL - KettyDo - Engineering Cloud',
        task: 'cloud',
      },
      {
        customer: 'Kettydo+ Srl',
        project: 'CLT-0541/24 - CL - KettyDo - Rinnovo MS 2024',
        task: 'Area 1',
      },
      {
        customer: 'Kettydo+ Srl',
        project: 'CLT-0541/24 - CL - KettyDo - Rinnovo MS 2024',
        task: 'Area 2',
      },
      {
        customer: 'Kettydo+ Srl',
        project: 'CLT-0541/24 - CL - KettyDo - Rinnovo MS 2024',
        task: 'Incident',
      },
      {
        customer: 'Kettydo+ Srl',
        project: 'CLT-0545/24 - CL - KettyDo - Engineering Cloud T&M',
        task: 'cloud',
      },
      {
        customer: 'Kuba Italia',
        project: 'CLT-0088/22 - CL - Kuba Vixtechnology - MS 24x7',
        task: 'MS Kuba Italia AREA-1',
      },
      {
        customer: 'Kuba Italia',
        project: 'CLT-0088/22 - CL - Kuba Vixtechnology - MS 24x7',
        task: 'MS Kuba Italia INCIDENT',
      },
      {
        customer: 'Leithà',
        project:
          'CLT-0076/23 - CL - Leithà - Redshift QuickSights and Networking-Security',
        task: 'Attività di Engineering',
      },
      {
        customer: 'Loacker',
        project: 'CLT-0078/23 - CL - Loacker - set up PaloAlto Firewall',
        task: 'set up PaloAlto Firewall',
      },
      {
        customer: 'Loacker',
        project: 'CLT-0115/21 - CL - Loacker - MS on SAP Lug 2021 Giu 2024',
        task: 'MS Loacker AREA-1',
      },
      {
        customer: 'Loacker',
        project: 'CLT-0115/21 - CL - Loacker - MS on SAP Lug 2021 Giu 2024',
        task: 'MS Loacker INCIDENT',
      },
      {
        customer: 'Loacker',
        project: 'CLT-0362/24 - CL - Loacker - supporto a migrazione',
        task: 'sviluppo',
      },
      {
        customer: 'MajorOne',
        project: 'CLT-0220/23 - CL - Major - MS for 2023',
        task: 'MS MajorOne AREA-1',
      },
      {
        customer: 'MajorOne',
        project: 'CLT-0220/23 - CL - Major - MS for 2023',
        task: 'MS MajorOne INCIDENT',
      },
      {
        customer: 'MajorOne',
        project: 'CLT-0488/24 - CL - MAJOR 1 - MS for 2024',
        task: 'MS MajorOne AREA-1',
      },
      {
        customer: 'MajorOne',
        project: 'CLT-0488/24 - CL - MAJOR 1 - MS for 2024',
        task: 'MS MajorOne INCIDENT',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0426/24 - CL - MOOVTECH - Discovery',
        task: 'Discovery',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT 26: 29/05 - 14/06',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT 27: 17/06 - 28/06',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT 28: 01/07 - 12/07',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT 29: 15/07 - 26/07',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT06: 2-9 gennaio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT07: 10-16 gennaio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT08: 17-23 gennaio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT09: 24-30 gennaio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT10: 31-6 febbraio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT11 7-13 febbraio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT12 14-20 febbraio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT13 21-27 febbraio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT14 28-5 marzo',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT15 6-12 marzo',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT16 13-19 marzo',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT17 20-26 marzo',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT18 27-9 aprile',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT19 10-16 aprile',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT20 17-23 aprile',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT21 24-30 aprile',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT22 1-7 maggio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT23 8-14 maggio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT24 15-21 maggio',
      },
      {
        customer: 'Moov-Tech Srl',
        project: 'CLT-0427/24 - CL - Moov-Tech - SOR Sviluppo e Cloud',
        task: 'IT25 22-28 maggio',
      },
      {
        customer: 'Ncore Srl',
        project: 'CLT-0596/24 - CL - NCORE - Architectural Clash',
        task: '(Without task)',
      },
      {
        customer: 'Next srl',
        project: 'CLT-0224/23 - FL - Next - Supporto Cloud AWS',
        task: 'cloud',
      },
      {
        customer: 'OverIT',
        project: 'CLT-0041/23 - CL - OverIT - MS for 2023 2024',
        task: 'MS OverIT - AREA-1',
      },
      {
        customer: 'OverIT',
        project: 'CLT-0041/23 - CL - OverIT - MS for 2023 2024',
        task: 'MS OverIT - AREA-2',
      },
      {
        customer: 'OverIT',
        project: 'CLT-0041/23 - CL - OverIT - MS for 2023 2024',
        task: 'MS OverIT - FINOPS',
      },
      {
        customer: 'OverIT',
        project: 'CLT-0041/23 - CL - OverIT - MS for 2023 2024',
        task: 'MS OverIT - INCIDENT',
      },
      {
        customer: 'OverIT',
        project: 'CLT-0249-23 - CL - OverIT - Evolutive Area 2 T&M',
        task: 'Evolutive Area 2 T&M',
      },
      {
        customer: 'Pat',
        project: 'CLT-0035/22 - CL - PAT - Offerta servizi Professionali AWS',
        task: 'Attività di Engineering',
      },
      {
        customer: 'Prometeia S.p.a.',
        project: 'CLT-0441/24 - CL - Prometeia Rinnovo Contratto 2024',
        task: 'Attività UX',
      },
      {
        customer: 'Prometeia S.p.a.',
        project: 'CLT-0441/24 - CL - Prometeia Rinnovo Contratto 2024',
        task: 'Banca Generali',
      },
      {
        customer: 'Prometeia S.p.a.',
        project: 'CLT-0441/24 - CL - Prometeia Rinnovo Contratto 2024',
        task: 'Banca Patrimoni Sella',
      },
      {
        customer: 'Prometeia S.p.a.',
        project: 'CLT-0441/24 - CL - Prometeia Rinnovo Contratto 2024',
        task: 'BPER',
      },
      {
        customer: 'Prometeia S.p.a.',
        project: 'CLT-0441/24 - CL - Prometeia Rinnovo Contratto 2024',
        task: 'Cherry',
      },
      {
        customer: 'Prometeia S.p.a.',
        project: 'CLT-0441/24 - CL - Prometeia Rinnovo Contratto 2024',
        task: 'Credem',
      },
      {
        customer: 'Prometeia S.p.a.',
        project: 'CLT-0441/24 - CL - Prometeia Rinnovo Contratto 2024',
        task: 'Monte dei Paschi di Siena',
      },
      {
        customer: 'Prometeia S.p.a.',
        project: 'CLT-0441/24 - CL - Prometeia Rinnovo Contratto 2024',
        task: 'Poste',
      },
      {
        customer: 'Repower Vendita Italia S.p.A.',
        project: 'CLT-0534/24 - CL - Repower - Consulenza e supporto 2024',
        task: 'cloud',
      },
      {
        customer: 'Repower Vendita Italia S.p.A.',
        project:
          'CLT-0631/24 - CL - Repower - Consulenza e supporto Lug-Dic 24',
        task: 'cloud',
      },
      {
        customer: 'Romagna Servizi Industriali s.r.l.',
        project: 'CLT-0485/24 - CL - Romagna Servizi - T&M 10 giornate',
        task: 'Manutenzione',
      },
      {
        customer: 'Romagna Servizi Industriali s.r.l.',
        project: 'CLT-0485/24 - CL - Romagna Servizi - T&M 10 giornate',
        task: 'sviluppo',
      },
      {
        customer: 'Romagna Servizi Industriali s.r.l.',
        project: 'CLT-0592-24 - CL - Blubai sviluppo app 2024 T&M 20 giornate',
        task: 'sviluppo',
      },
      {
        customer: 'SCM Group S.p.a.',
        project: 'PROVVISORIO CLT-0512/24 - CL - SCM - Sviluppo 2024',
        task: '(Without task)',
      },
      {
        customer: 'Scouting S.p.a.',
        project:
          'CLT-0424/24 - CL - Scouting - Sviluppo applicativo Ottobre 23',
        task: 'Manutenzione Ordinaria e straordinaria',
      },
      {
        customer: 'Scouting S.p.a.',
        project: 'CLT-0522/24 - CL - Scouting - Rinnovo 2024 T&M',
        task: 'Manutenzione',
      },
      {
        customer: 'Scouting S.p.a.',
        project: 'CLT-0522/24 - CL - Scouting - Rinnovo 2024 T&M',
        task: 'sviluppo',
      },
      {
        customer: 'Senato',
        project:
          'CLT-0543/24 - CL - Senato - Hosting-Assistenza-Manutenzione 2024',
        task: 'Classificazione Leggi SaaS - Discovery',
      },
      {
        customer: 'Senato',
        project:
          'CLT-0543/24 - CL - Senato - Hosting-Assistenza-Manutenzione 2024',
        task: 'Data - PoC Generative AI',
      },
      {
        customer: 'Sinapsi S.r.l.',
        project: 'CLT-0430/24 - CL - Sinapsi - Engineering 2024',
        task: 'Cloud Engineering',
      },
      {
        customer: 'Sinapsi S.r.l.',
        project: 'CLT-0430/24 - CL - Sinapsi - Engineering 2024',
        task: 'Digital trainer - PoC',
      },
      {
        customer: 'Sinapsi S.r.l.',
        project: 'CLT-0430/24 - CL - Sinapsi - Engineering 2024',
        task: 'Supporto manageriale C Level',
      },
      {
        customer: 'Sinapsi S.r.l.',
        project: 'CLT-0430/24 - CL - Sinapsi - Engineering 2024',
        task: 'Supporto per servizi di recruiting',
      },
      {
        customer: 'Sinapsi S.r.l.',
        project: 'CLT-0430/24 - CL - Sinapsi - Engineering 2024',
        task: 'Sviluppo',
      },
      {
        customer: 'Sinapsi S.r.l.',
        project: 'CLT-0430/24 - CL - Sinapsi - Engineering 2024',
        task: 'UX/UI',
      },
      {
        customer: 'Tannico S.p.a.',
        project: 'CLT-0215/23 - CL - Tannico - Managed service 2023/2024',
        task: 'AREA 1',
      },
      {
        customer: 'Tannico S.p.a.',
        project: 'CLT-0215/23 - CL - Tannico - Managed service 2023/2024',
        task: 'AREA 2',
      },
      {
        customer: 'Tannico S.p.a.',
        project: 'CLT-0215/23 - CL - Tannico - Managed service 2023/2024',
        task: 'INCIDENT',
      },
      {
        customer: 'Tannico S.p.a.',
        project:
          'CLT-0302/23 - CL - Tannico - affiancamento supporto AWS Estensione Aprile 2023',
        task: '(Without task)',
      },
      {
        customer: 'Tannico S.p.a.',
        project:
          'CLT-0398/24 - CL - Tannico - Gestione Ordini_Managed Software',
        task: 'Change Request',
      },
      {
        customer: 'Tannico S.p.a.',
        project:
          'CLT-0398/24 - CL - Tannico - Gestione Ordini_Managed Software',
        task: 'Managed Software',
      },
      {
        customer: 'Tannico S.p.a.',
        project:
          'CLT-0502/24 - CL - Tannico Training on the job T&M - Gestione ordini',
        task: 'sviluppo',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0483/24 - CL - Technogym - 6° addendum Dicembre 23',
        task: 'Progetto Windchill',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0483/24 - CL - Technogym - 6° addendum Dicembre 23',
        task: 'sviluppo BE e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0483/24 - CL - Technogym - 6° addendum Dicembre 23',
        task: 'sviluppo BE parts planning',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0483/24 - CL - Technogym - 6° addendum Dicembre 23',
        task: 'Sviluppo ETL Cloud (dove ci vanno le ore di Christian che costano di più)',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0483/24 - CL - Technogym - 6° addendum Dicembre 23',
        task: 'Sviluppo Fe e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0513-24 - CL - Technogym - 7° addendum Gennaio 24',
        task: 'Progetto Windchill',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0513-24 - CL - Technogym - 7° addendum Gennaio 24',
        task: 'sviluppo BE e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0513-24 - CL - Technogym - 7° addendum Gennaio 24',
        task: 'sviluppo BE parts planning',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0513-24 - CL - Technogym - 7° addendum Gennaio 24',
        task: 'Sviluppo ETL backend',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0513-24 - CL - Technogym - 7° addendum Gennaio 24',
        task: 'Sviluppo ETL Cloud (dove ci vanno le ore di Christian che costano di più)',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0529/24 - CL - Technogym - 8° addendum Febbraio 24',
        task: 'sviluppo BE e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0529/24 - CL - Technogym - 8° addendum Febbraio 24',
        task: 'Sviluppo Fe e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0554-24 - CL - Technogym - 9° addendum Marzo 24',
        task: 'sviluppo BE e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0554-24 - CL - Technogym - 9° addendum Marzo 24',
        task: 'sviluppo BE parts planning',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0554-24 - CL - Technogym - 9° addendum Marzo 24',
        task: 'Sviluppo ETL Cloud (dove ci vanno le ore di Christian che costano di più)',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0554-24 - CL - Technogym - 9° addendum Marzo 24',
        task: 'Sviluppo Fe e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0557-24 - CL - Technogym - 10° addendum Marzo 24',
        task: 'Progetto Windchill',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0557-24 - CL - Technogym - 10° addendum Marzo 24',
        task: 'sviluppo BE e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0557-24 - CL - Technogym - 10° addendum Marzo 24',
        task: 'sviluppo BE parts planning',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0557-24 - CL - Technogym - 10° addendum Marzo 24',
        task: 'Sviluppo ETL Cloud (dove ci vanno le ore di Christian che costano di più)',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0557-24 - CL - Technogym - 10° addendum Marzo 24',
        task: 'Sviluppo Fe e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0568-24 - CL - Technogym - 11° addendum Aprile 24',
        task: 'Progetto Windchill',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0568-24 - CL - Technogym - 11° addendum Aprile 24',
        task: 'sviluppo BE e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0568-24 - CL - Technogym - 11° addendum Aprile 24',
        task: 'sviluppo BE parts planning',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0568-24 - CL - Technogym - 11° addendum Aprile 24',
        task: 'Sviluppo ETL Cloud (dove ci vanno le ore di Christian che costano di più)',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0568-24 - CL - Technogym - 11° addendum Aprile 24',
        task: 'Sviluppo Fe e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0590-24 - CL - Technogym - 12° addendum Maggio 24',
        task: 'Progetto Windchill',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0590-24 - CL - Technogym - 12° addendum Maggio 24',
        task: 'sviluppo BE e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0590-24 - CL - Technogym - 12° addendum Maggio 24',
        task: 'sviluppo BE parts planning',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0590-24 - CL - Technogym - 12° addendum Maggio 24',
        task: 'Sviluppo ETL Cloud (dove ci vanno le ore di Christian che costano di più)',
      },
      {
        customer: 'Technogym S.p.a.',
        project: 'CLT-0590-24 - CL - Technogym - 12° addendum Maggio 24',
        task: 'Sviluppo Fe e-services',
      },
      {
        customer: 'Technogym S.p.a.',
        project:
          'CLT-0621-24 - CL - Technogym - 13° addendum 10 giornate Giugno 24',
        task: 'progetto WUM/Windchill',
      },
      {
        customer: 'THRON',
        project: 'CLT-0312/23 - CL - THRON - MS Managed Service',
        task: 'AREA 1',
      },
      {
        customer: 'THRON',
        project: 'CLT-0312/23 - CL - THRON - MS Managed Service',
        task: 'INCIDENT',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 17 dal 26/02 al 03/03',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 18 dal 04/03 al 10/03',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 19 dal 11/03 al 17/03',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 20 dal 18/03 al 24/03',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 21 dal 25/03 al 31/03',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 22 dal 01/04 al 07/04',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 23 dal 08/04 al 14/04',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 24 dal 15/04 al 21/04',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 25 dal 22/04 al 28/04',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 26 dal 29/04 al 05/05',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 27 dal 06/05 al 12/05',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 28 dal 13/05 al 19/05',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 29 dal 20/05 al 26/05',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 30 dal 27/05 al 02/06',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 31 dal 03/06 al 09/06',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 32 dal 10/06 al 16/06',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 33 dal 17/06 al 23/06',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 34 dal 24/06 al 30/06',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 35 dal 08/07 al 14/07',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT 36 dal 15/07 al 21/07',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT12: 22/01 - 28/01',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT13: 29/01 - 04/02',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'IT14: 05/02 - 11/02',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'ITERAZION 10: 8 - 14 gennaio',
      },
      {
        customer: 'THRON',
        project: 'CLT-0341/23 - CL - THRON - Engineering Cloud contratto Sor',
        task: 'ITERAZIONE 11: 15 - 21 gennaio',
      },
      {
        customer: 'Union Srl',
        project:
          'CLT-0572/24 - CL - Union Energia - Consolidamento infrastruttura Cloud',
        task: 'cloud',
      },
      {
        customer: 'Yellow Factory',
        project: 'PROVVISORIO Yellow Factory',
        task: 'Sviluppo Infrastruttura',
      },
    ]

    for (const task of input) {
      const customerProject = `${task.customer}#${task.project}`
      const updateParams = {
        TableName: getTableName('Task'),
        Key: {
          customerProject: { S: customerProject },
          company: { S: company },
        },
        UpdateExpression:
          'SET projectType = :projectType, inactive = :inactive ADD tasks :task',
        ExpressionAttributeValues: {
          ':task': {
            SS: [task.task],
          },
          ':projectType': { S: projectType },
          ':inactive': { BOOL: false },
        },
      }
      try {
        await this.dynamoDBClient.send(new UpdateItemCommand(updateParams))
      } catch (error) {
        console.log(error)
      }
    }
  }

  private getTimeEntry(
    item: Record<string, AttributeValue>,
  ): TimeEntryRowType[] {
    const resultForCompany: TimeEntryRowType[] = []

    item.tasks?.SS?.forEach((taskItem) => {
      const [customer, project, task, hours] = taskItem.split('#')
      resultForCompany.push({
        user: item.uid?.S ?? '',
        date: item.timeEntryDate?.S ?? '',
        company: item.company?.S ?? '',
        customer: customer,
        project: project,
        task: task,
        hours: parseFloat(hours),
        description: item.description?.S ?? '',
        startHour: item.startHour?.S ?? '',
        endHour: item.endHour?.S ?? '',
      })
    })
    return resultForCompany
  }
}
