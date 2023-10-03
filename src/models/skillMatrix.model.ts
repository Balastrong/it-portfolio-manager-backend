import { Static, Type } from '@sinclair/typebox'

export const SkillMatrixRow = Type.Object({
  uid: Type.String(),
  company: Type.String(),
  crew: Type.String(),
  skill: Type.String(),
  score: Type.Number(),
  updatedAt: Type.String(),
})

export const SkillMatrix = Type.Array(SkillMatrixRow)

export type SkillMatrixType = Static<typeof SkillMatrix>

export const SkillMatrixReadParams = Type.Object({
  uid: Type.String(),
})

export type SkillMatrixReadParamsType = Static<typeof SkillMatrixReadParams>
