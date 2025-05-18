import { createSlice, PayloadAction } from '@reduxjs/toolkit'

interface IDisplay {
    isLoginShown: boolean
}


const initialState: IDisplay = {
    isLoginShown: false
}

const displaySlice = createSlice({
    name: 'display',
    initialState,
    reducers: {
        setIsLoginShown: (state, action: PayloadAction<boolean>) => {
            state.isLoginShown = action.payload
        }
    }
})

export const { setIsLoginShown } = displaySlice.actions
export default displaySlice.reducer