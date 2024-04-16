import { useContext, useState } from "react";
import { CartContext } from "../AppContext";
import toast from "react-hot-toast";
import MenuItemTile from "@/app/components/menu/MenuItemTile";
import Image from "next/image";

export default function MenuItem(menuItem) {
    const {image,name,basePrice,sizes,extraIngredientPrices,} = menuItem;
    const [selectedSize, setSelectedSize] = useState(sizes?.[0] || null);
    const [selectedExtras, setSelectedExtras] = useState([]);
    const [showPopup, setShowPopup] = useState(false);
    const {addToCart} = useContext(CartContext);

    function handleAddToCartButtonClick() {
    const hasOptions = sizes.length > 0 && extraIngredientPrices.length > 0;
        if (hasOptions && !showPopup) {
        setShowPopup(true);
        return;
    }
        addToCart(menuItem, selectedSize, selectedExtras );    
        setShowPopup(false)
        toast.success('Added to cart', {
            position: "top-center",
        });
    }

    function handleExtraClick(ev, extra){
        const checked = ev.target.checked;
        if (checked) {
            setSelectedExtras(prev => [...prev, extra]);
        } else {
            setSelectedExtras(prev => {
                return prev.filter(e => e.name !== extra.name);
            }); 
        }
    }

    let selectedPrice = basePrice;
    if (selectedSize) {
        selectedPrice += selectedSize.price;
    }
    if (selectedExtras?.length > 0) {
        for (const extra of selectedExtras) {
            selectedPrice += extra.price;
        }
    }

    return(
        <>
            {showPopup && (
                <div 
                onClick={() => setShowPopup(false)}
                className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center">
                    <div
                    onClick={ev => ev.stopPropagation()} 
                    className="my-8 bg-white p-2 rounded-lg ">
                        <div className="overflow-y-scroll p-2 " 
                        style={{maxHeight:'calc(100vh - 90px)'}}>
                            {image && (    
                                <Image className="mx-auto" src={image} alt={name} width={200} height={200} />
                            )}
                            {!image && (
                                <div className="text-center bg-gray-200 p-4 text-gray-500 max-w-2xl rounded-lg mb-1">
                                    no image
                                </div>
                            )}
                            <h2 className="text-lg font-bold text-center">{name}</h2>
                            {sizes?.length > 0 && (
                                <div className="py-2">
                                    <h3 className="text-center text-gray-700">Sizes</h3>
                                    {sizes.map(size => (
                                        <label
                                        key={size._id}
                                        className="flex items-center gap-2 p-2 border rounded-md mb-1">
                                               <input
                                            onChange={() => setSelectedSize(size)}
                                            checked={selectedSize?.name === size.name}
                                            type="radio"
                                            
                                            name="size"/> 
                                            {size.name} ₱{basePrice + size.price}
                                        </label>
                                    ))}
                                </div>
                            )}
                            {extraIngredientPrices?.length > 0 && (
                                <div className="py-2">
                                    <h3 className="text-center text-gray-700">Additional</h3>
                                    {extraIngredientPrices.map(extra => (
                                        <label
                                            key={extra._id}
                                            className="flex items-center gap-2 p-2 border rounded-md mb-1">
                                                <input 
                                                type="checkbox"
                                               
                                                onChange={ev => handleExtraClick(ev,extra)}
                                                name={extra.name}/>

                                            {extra.name} + ₱{extra.price}
                                        </label>
                                    ))}
                                </div>
                            )}
                            <button 
                                onClick={handleAddToCartButtonClick}
                                className="bg-primary text-sm text-white sticky bottom-2" 
                                type="button">Add to Cart  ₱{selectedPrice}
                            </button>
                            <button 
                                className="mt-1 text-sm hover:bg-red-500 text-primary hover:text-white" 
                                onClick={() => setShowPopup(false)}>Cancel
                            </button>
                        </div>
                    </div>
                </div>
            )}
            <MenuItemTile onAddToCart={handleAddToCartButtonClick} {...menuItem} />
        </>
    );
}



