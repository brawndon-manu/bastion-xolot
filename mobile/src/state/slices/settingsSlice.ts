import { createSlice, PayloadAction } from "@reduxjs/toolkit";

type SettingsState = {
  monitorOnly: boolean;
};

const initialState: SettingsState = {
  monitorOnly: false
};

const settingsSlice = createSlice({
  name: "settings",
  initialState,
  reducers: {
    setMonitorOnly: (s, a: PayloadAction<boolean>) => {
      s.monitorOnly = a.payload;
    }
  }
});

export const { setMonitorOnly } = settingsSlice.actions;
export default settingsSlice.reducer;
