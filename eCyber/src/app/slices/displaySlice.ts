import { createSlice, PayloadAction } from "@reduxjs/toolkit";

// ✅ Define the interface for the state
interface IDisplay {
  isAuthModalOpen: boolean;
}

// ✅ Define the initial state
const initialState: IDisplay = {
  isAuthModalOpen: false,
};

// ✅ Create the slice
const displaySlice = createSlice({
  name: "display",
  initialState,
  reducers: {
    setAuthModalState: (state, action: PayloadAction<boolean>) => {
      state.isAuthModalOpen = action.payload;
    },
  },
});

// ✅ Export actions and reducer
export const { setAuthModalState } = displaySlice.actions;
export default displaySlice.reducer
