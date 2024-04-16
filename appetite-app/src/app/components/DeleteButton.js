import { useState } from "react";
import Trash from "./icons/Trash";

export default function DeleteButton({onDelete}){
    const [showConfirm, setShowConfirm] = useState(false);
    
    if (showConfirm) {
        return (
            <div className="fixed bg-black/70 inset-0 flex items-center h-full justify-center">
                <div className="bg-white p-4 rounded-lg">
                    <div>
                        Are you sure you want to delete this item?
                    </div>
                    <div className="flex gap-2">
                        <button type="button" 
                        onClick={() => setShowConfirm(false)}>
                            Cancel
                        </button>
                        <button type="button" 
                        onClick={() => {onDelete(); setShowConfirm(false); }}
                        className="bg-red-400 text-white">
                            confirm,&nbsp;Delete
                        </button>
                    </div>
                </div>
            </div>
        );
    }
    return(
        <div className="max-w-2xl mx-auto">
            <button className="bg-red-400 hover:bg-red-500 text-white" type="button" onClick={() => setShowConfirm(true)}>
                <Trash />
            </button>
        </div>
        
    );
}
