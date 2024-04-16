export default function AddToCartButton({hasSizesOrExtras, onClick, basePrice}){
    return(
        <button 
            type="button"
            onClick={onClick}
            className="text-nowrap mt-4 bg-primary text-white text-sm rounded-full px-8 py-2">
                {hasSizesOrExtras ?(
                    <span>Add to cart ₱{basePrice}</span>
                ):(
                    <span>Add to cart ₱{basePrice}</span>
                )}
        </button>
    )
}