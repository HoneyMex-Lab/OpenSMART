interface IdsFilterState {
  tab: string;
  timeframe: string;
  customStart: string;
  customEnd: string;
  q: string;
  topN: number;
  filters: Record<string, string>;
}

const defaults: IdsFilterState = {
  tab: 'summary',
  timeframe: '1d',
  customStart: '',
  customEnd: '',
  q: '',
  topN: 10,
  filters: {},
};

let _state: IdsFilterState = { ...defaults };

export const idsStore = {
  get: (): IdsFilterState => ({ ..._state, filters: { ..._state.filters } }),
  set: (patch: Partial<IdsFilterState>) => { _state = { ..._state, ...patch }; },
};
