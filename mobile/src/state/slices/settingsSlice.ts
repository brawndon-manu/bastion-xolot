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
    setMonitorOnly: (state, action: PayloadAction<boolean>) => {
      state.monitorOnly = action.payload;
    }
  }
});

export const { setMonitorOnly } = settingsSlice.actions;
export default settingsSlice.reducer;
