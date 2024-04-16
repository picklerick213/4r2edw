import Image from "next/image";
import AddToCartButton from "@/app/components/menu/AddToCartButton";

export default function MenuItemTile({onAddToCart, ...item}) {
    const {image, name, basePrice, sizes, extraIngredientPrices} = item;
    const hasSizesOrExtras = sizes?.length > 0 || extraIngredientPrices?.length > 0;
    return (
        <div className="bg-gray-300 p-4 rounded-lg text-center my-5 
        hover:bg-white transition-all hover:shadow-xl hover:shadow-black-300">
            <div className="text-center">
            {image && (
                <Image className="rounded-lg mb-1" 
                src={image} width={250} height={250} alt={'avatar'} />
            )}
            {!image && (
                <div className="text-center bg-gray-200 p-4 text-gray-500 rounded-lg mb-1">
                    no image
                </div>
            )}
            </div>
            <h4 className="font-semibold my-3">{name}</h4>
                <AddToCartButton 
                hasSizesOrExtras={hasSizesOrExtras}
                onClick={onAddToCart}
                basePrice={basePrice} />
        </div>
    );
}