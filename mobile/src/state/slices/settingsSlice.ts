import { createSlice, PayloadAction } from "@reduxjs/toolkit";

export type TranslationLevel = "nerd" | "standard" | "grandma";

type SettingsState = {
  monitorOnly: boolean;
  translationLevel: TranslationLevel;
};

const initialState: SettingsState = {
  monitorOnly: false,
  translationLevel: "standard",
};

const settingsSlice = createSlice({
  name: "settings",
  initialState,
  reducers: {
    setMonitorOnly: (state, action: PayloadAction<boolean>) => {
      state.monitorOnly = action.payload;
    },
    setTranslationLevel: (state, action: PayloadAction<TranslationLevel>) => {
      state.translationLevel = action.payload;
    },
  }
});

export const { setMonitorOnly, setTranslationLevel } = settingsSlice.actions;
export default settingsSlice.reducer;
