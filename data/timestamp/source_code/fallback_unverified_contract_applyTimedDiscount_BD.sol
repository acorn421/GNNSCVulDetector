/*
 * ===== SmartInject Injection Details =====
 * Function      : applyTimedDiscount
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the discount system relies on block.timestamp (now) for time-sensitive operations. The vulnerability is stateful and multi-transaction: 1) Owner sets a timed discount using applyTimedDiscount(), 2) Users claim discount eligibility with claimDiscount(), 3) Users get discounted prices with getDiscountedPrice(). Miners can manipulate timestamps within the 15-second tolerance to either extend discount periods, allow expired discounts to be claimed, or prevent legitimate users from claiming discounts. The state persists across transactions through discountStartTime, discountEndTime, and lastDiscountClaim mappings, making this exploitable only through multiple transactions where timestamp manipulation can accumulate advantages.
 */
pragma solidity ^0.4.11;

contract mortal
{
    address owner;

    function mortal() { owner = msg.sender; }
    function kill() { if(msg.sender == owner) selfdestruct(owner); }
}

contract SandwichShop is mortal
{

    struct Sandwich
    {
        uint sandwichID;
        string sandwichName;
        string sandwichDesc;
        string calories;
        uint price;
        uint availableQuantity;
    }

    struct OrderedSandwich
    {
        uint sandID;
        string notes;
        uint price;
    }

    Sandwich[5] shopSandwich;
    mapping( address => OrderedSandwich[] ) public cart; 

    function SandwichShop() public
    {
        shopSandwich[0].sandwichID = 0;
        shopSandwich[0].sandwichName = "100: Ham & Swiss";
        shopSandwich[0].sandwichDesc = "Ham Swiss Mustard Rye";
        shopSandwich[0].calories = "450 calories";
        shopSandwich[0].price = 5;
        shopSandwich[0].availableQuantity = 200;

        shopSandwich[1].sandwichID = 1;
        shopSandwich[1].sandwichName = "101: Turkey & Pepperjack";
        shopSandwich[1].sandwichDesc = "Turkey Pepperjack Mayo White Bread";
        shopSandwich[1].calories = "500 calories";
        shopSandwich[1].price = 5;
        shopSandwich[1].availableQuantity = 200;

        shopSandwich[2].sandwichID = 2;
        shopSandwich[2].sandwichName = "102: Roast Beef & American";
        shopSandwich[2].sandwichDesc = "Roast Beef Havarti Horseradish White Bread";
        shopSandwich[2].calories = "600 calories";
        shopSandwich[2].price = 5;
        shopSandwich[2].availableQuantity = 200;

        shopSandwich[3].sandwichID = 3;
        shopSandwich[3].sandwichName = "103: Reuben";
        shopSandwich[3].sandwichDesc = "Corned Beef Sauerkraut Swiss Rye";
        shopSandwich[3].calories = "550 calories";
        shopSandwich[3].price = 5;
        shopSandwich[3].availableQuantity = 200;

        shopSandwich[4].sandwichID = 4;
        shopSandwich[4].sandwichName = "104: Italian";
        shopSandwich[4].sandwichDesc = "Salami Peppers Provolone Oil Vinegar White";
        shopSandwich[4].calories = "500 calories";
        shopSandwich[4].price = 5;
        shopSandwich[4].availableQuantity = 200;
    }

    function getMenu() constant returns (string, string, string, string, string)
    {
        return (shopSandwich[0].sandwichName, shopSandwich[1].sandwichName,
                shopSandwich[2].sandwichName, shopSandwich[3].sandwichName,
                shopSandwich[4].sandwichName );
    }

    function getSandwichInfoCaloriesPrice(uint _sandwich) constant returns (string, string, string, uint)
    {
        if( _sandwich > 4 )
        {
            return ( "wrong ID", "wrong ID", "zero", 0);
        }
        else
        {
            return (shopSandwich[_sandwich].sandwichName, shopSandwich[_sandwich].sandwichDesc,
                shopSandwich[_sandwich].calories, shopSandwich[_sandwich].price);
        }
    }

    function addToCart(uint _orderID, string _notes) returns (uint)
    {
        OrderedSandwich memory newOrder;
        newOrder.sandID = _orderID;
        newOrder.notes = _notes;
        newOrder.price = shopSandwich[_orderID].price;

        return cart[msg.sender].push(newOrder);
    }

    function getCartLength() constant returns (uint)
    {
        return cart[msg.sender].length;
    }

    function readFromCart(uint _spot) constant returns (string)
    {
        return cart[msg.sender][_spot].notes;
    }

    function emptyCart() public
    {
        delete cart[msg.sender];
    }


    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint public discountStartTime;
    uint public discountEndTime;
    uint public discountPercentage;
    bool public discountActive;
    mapping(address => uint) public lastDiscountClaim;
    
    function applyTimedDiscount(uint _percentage, uint _durationMinutes) public {
        require(msg.sender == owner, "Only owner can set discount");
        require(_percentage <= 50, "Discount cannot exceed 50%");
        require(_durationMinutes > 0, "Duration must be positive");
        
        discountStartTime = now;
        discountEndTime = now + (_durationMinutes * 1 minutes);
        discountPercentage = _percentage;
        discountActive = true;
    }
    
    function claimDiscount() public returns (bool) {
        require(discountActive, "No active discount");
        require(now >= discountStartTime, "Discount not started yet");
        require(now <= discountEndTime, "Discount has expired");
        require(lastDiscountClaim[msg.sender] < discountStartTime, "Already claimed this discount");
        
        lastDiscountClaim[msg.sender] = now;
        return true;
    }
    
    function getDiscountedPrice(uint _sandwichId) public constant returns (uint) {
        require(_sandwichId < 5, "Invalid sandwich ID");
        
        if (discountActive && now >= discountStartTime && now <= discountEndTime && 
            lastDiscountClaim[msg.sender] >= discountStartTime) {
            uint originalPrice = shopSandwich[_sandwichId].price;
            uint discount = (originalPrice * discountPercentage) / 100;
            return originalPrice - discount;
        }
        
        return shopSandwich[_sandwichId].price;
    }
    // === END FALLBACK INJECTION ===

}