import {cartProductPrice} from "@/app/components/AppContext";
import Trash from "@/app/components/icons/Trash";
import Image from "next/image";

export default function CartProduct({product,onRemove}) {
  return (
    <div className="flex items-center gap-4 border-b py-4">
      <div className="w-24">
      {product.image && (
            <Image className="rounded-lg mb-1" 
            src={product.image} width={250} height={250} alt={'avatar'} />
        )}
        {!product.image&& (
            <div className="text-center bg-gray-200 p-4 text-gray-500 rounded-lg mb-1">
                no image
            </div>
        )}
      </div>
      <div className="grow">
        <h3 className="font-semibold">
          {product.name}
        </h3>
        {product.size && (
          <div className="text-sm">
            Size: <span>{product.size.name}</span>
          </div>
        )}
        {product.extras?.length > 0 && (
          <div className="text-sm text-gray-500">
            {product.extras.map(extra => (
              <div key={extra.name}>{extra.name} ${extra.price}</div>
            ))}
          </div>
        )}
      </div>
      <div className="text-lg font-semibold">
        ${cartProductPrice(product)}
      </div>
      {!!onRemove && (
        <div className="ml-2">
          <button
            type="button"
            onClick={() => onRemove(index)}
            className="p-2">
            <Trash />
          </button>
        </div>
      )}
    </div>
  );
}