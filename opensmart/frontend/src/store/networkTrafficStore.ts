interface NetworkTrafficFilterState {
  tab: string;
  timeframe: string;
  customStart: string;
  customEnd: string;
  q: string;
  topN: number;
  detailsTable: string;
}

const defaults: NetworkTrafficFilterState = {
  tab: 'summary',
  timeframe: '1d',
  customStart: '',
  customEnd: '',
  q: '',
  topN: 10,
  detailsTable: 'all_events',
};

let _state: NetworkTrafficFilterState = { ...defaults };

export const networkTrafficStore = {
  get: (): NetworkTrafficFilterState => ({ ..._state }),
  set: (patch: Partial<NetworkTrafficFilterState>) => { _state = { ..._state, ...patch }; },
};
