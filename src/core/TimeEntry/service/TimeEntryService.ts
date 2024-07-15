import { TaskRepositoryInterface } from '@src/core/Task/repository/TaskRepositoryInterface'
import {
  TimeEntryReadParamWithUserType,
  TimeEntryRowType,
  deleteTimeEntryWithUserType,
  CnaReadParamType,
  TimeEntriesForCnaType,
} from '../model/timeEntry.model'
import { TimeEntryRepositoryInterface } from '../repository/TimeEntryRepositoryInterface'
import { TaskNotExistsError } from '@src/core/customExceptions/TaskNotExistsError'
import { ProjectType } from '@src/core/Report/model/productivity.model'
import { UserProfileRepositoryInterface } from '@src/core/User/repository/UserProfileRepositoryInterface'

export class TimeEntryService {
  constructor(
    private timeEntryRepository: TimeEntryRepositoryInterface,
    private taskRepository: TaskRepositoryInterface,
    private userProfileRepository: UserProfileRepositoryInterface,
  ) {}

  async find(
    params: TimeEntryReadParamWithUserType,
  ): Promise<TimeEntryRowType[]> {
    return await this.timeEntryRepository.find(params)
  }

  async findTimeOffForCna(
    params: CnaReadParamType,
  ): Promise<TimeEntriesForCnaType[]> {
    const timeEntries = await this.timeEntryRepository.findTimeOffForCna(params)
    return []
    // return timeEntries.length > 0
    //   ? Promise.all(
    //       timeEntries.map(async (entry) => {
    //         const user =
    //           await this.userProfileRepository.getCompleteUserProfile(
    //             entry.user,
    //           )
    //         const response = {
    //           description: entry.task, //TODO
    //           user: {
    //             email: user?.uid ?? '',
    //             name: user?.name ?? '',
    //           },
    //           userId: user?.uid ?? '',
    //           billable: entry.projectType === ProjectType.BILLABLE,
    //           task: {
    //             name: entry.task,
    //           },
    //           project: {
    //             name: entry.project,
    //             billable: entry.projectType === ProjectType.BILLABLE,
    //             clientName: entry.project,
    //           },
    //           timeInterval: {
    //             start: entry.timeEntryDate,
    //             end: '',
    //             duration: entry.hours.toString(),
    //           },
    //         }
    //         console.log(JSON.stringify(response, null, 2))
    //         return response
    //       }),
    //     )
    //   : []
  }

  async saveMine(params: TimeEntryRowType): Promise<void> {
    const tasks = await this.taskRepository.getTasks({
      company: params.company,
      customer: params.customer,
      project: params.project,
    })
    if (!tasks.includes(params.task)) {
      throw new TaskNotExistsError()
    }
    return await this.timeEntryRepository.saveMine(params)
  }

  async delete(params: deleteTimeEntryWithUserType): Promise<void> {
    await this.timeEntryRepository.delete(params)
  }
}
