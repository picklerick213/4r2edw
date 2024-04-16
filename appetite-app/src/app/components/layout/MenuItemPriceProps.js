import Trash from "@/app/components/icons/Trash";
import Plus from "@/app/components/icons/Plus";
import ChevronUp from '@/app/components/icons/ChevronUp';
import ChevronDown from '@/app/components/icons/ChevronDown';
import { useState } from "react";

export default function MenuItemPriceProps({name,addLabel,props,setProps}){


  const [isOpen, setIsOpen] = useState(false);


    function addProp() {
      setProps(oldProps => {
        return [...oldProps, {name:'', price:0}];
      });
    }

    function editProp(ev, index, prop) {
      const newValue = ev.target.value;
      setProps(prevSizes => {
        const newSizes = [...prevSizes];
        newSizes[index][prop] = newValue;
        return newSizes;
      });
    }

    function removeProp(indexToRemove) {
      setProps(prev => prev.filter((v,index) => index !== indexToRemove));
    }
  return(

      <div className="bg-gray-200 p-2 rounded-md mb-2">
          <button type="button" 
                  onClick={() => setIsOpen(prev => !prev)}
                  className="inline-flex p-1 border-0 justify-start">
                    {isOpen && (
                      <ChevronUp className="w-4 h-4 mb-1"/>
                    )}
                    {!isOpen && (
                      <ChevronDown className="w-4 h-4 mt-1"/>
                    )}
                <span>{name}</span>
                <span>({props?.length})</span>
          </button>

          <div className={isOpen ? 'block' : 'hidden'}>
          {props?.length > 0 && props.map((size,index) => (
        <div key={index} className="flex items-end gap-1">
          <div>
            <label>Name</label>
            <input type="text" placeholder="Size name" onChange={ev => editProp(ev, index, 'name')} value={size.name}/>
          </div>
          <div>
            <label>Extra price</label>
            <input type="text" placeholder="Extra Price" onChange={ev => editProp(ev, index, 'price')} value={size.price}/>
          </div>
          <div className="item">
            <button 
            className="bg-white mb-3 px-2.5"
            type="button"
            onClick={() => removeProp(index)}>
              <Trash className="w-4 h-4"/>
            </button>
          </div>
        </div>
      ))}
      <button type="button" 
              onClick={addProp} 
              className="bg-white items-center">
                <Plus className="w-4 h-4"/>
                <span>{addLabel}</span>
      </button>
          </div>
    </div>
  );
}