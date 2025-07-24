/*
 * ===== SmartInject Injection Details =====
 * Function      : buyObject
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction Timestamp Dependence vulnerability through several mechanisms:
 * 
 * **1. Specific Changes Made:**
 * - Added `lastPurchaseTime` mapping to track when each user last purchased
 * - Added `purchaseCount` mapping to track purchase frequency per user
 * - Implemented time-based cooldown using `block.timestamp` comparison
 * - Added dynamic pricing that changes based on elapsed time since initialization
 * - Created `calculateTimeBasedPrice()` function that uses `block.timestamp` for price calculation
 * - Added `initializePricing()` function to set the initial timestamp reference
 * 
 * **2. Multi-Transaction Exploitation Scenarios:**
 * 
 * **Scenario A - Cooldown Bypass:**
 * - Transaction 1: User makes initial purchase, `lastPurchaseTime[user] = block.timestamp`
 * - Miner manipulation: Miner can manipulate subsequent block timestamps within ~15 second tolerance
 * - Transaction 2: User attempts second purchase before cooldown expires, but miner manipulates `block.timestamp` to make it appear cooldown has passed
 * - Exploitation: User bypasses intended 5-minute cooldown through miner collusion
 * 
 * **Scenario B - Price Manipulation:**
 * - Transaction 1: Admin calls `initializePricing()` to set `basePriceTimestamp = block.timestamp`
 * - State accumulation: Price increases every hour based on `block.timestamp` difference
 * - Transaction 2+: Users make purchases at different times, but miners can manipulate `block.timestamp` to:
 *   - Make users pay higher prices by advancing timestamp
 *   - Allow users to pay lower prices by keeping timestamp lower
 *   - Create arbitrage opportunities across multiple transactions
 * 
 * **Scenario C - Coordinated Attack:**
 * - Transaction 1: Attacker makes initial purchase to establish `lastPurchaseTime`
 * - Transaction 2: Attacker waits for price increase window
 * - Transaction 3: Miner (collaborating with attacker) manipulates `block.timestamp` to create favorable pricing
 * - Transaction 4: Attacker makes bulk purchases at manipulated prices
 * 
 * **3. Why Multiple Transactions Are Required:**
 * 
 * - **State Dependency**: The vulnerability relies on stored state (`lastPurchaseTime`, `basePriceTimestamp`) that must be established in previous transactions
 * - **Temporal Accumulation**: The price calculation depends on time elapsed since initialization, requiring the passage of time across multiple blocks
 * - **Cooldown Mechanism**: The cooldown check requires a previous purchase to establish the baseline timestamp
 * - **Miner Coordination**: Effective exploitation requires miners to manipulate timestamps across multiple blocks in a coordinated manner
 * 
 * **4. Realistic Vulnerability Aspects:**
 * 
 * - **Natural Integration**: Time-based pricing and cooldowns are common in gaming/farming contracts
 * - **Subtle Manipulation**: The ~15-second timestamp manipulation window is realistic and often overlooked
 * - **Economic Incentive**: Price manipulation creates clear economic incentives for miners to participate
 * - **State Persistence**: The vulnerability persists across transactions through stored mappings
 * 
 * This creates a realistic, exploitable timestamp dependence vulnerability that requires multiple transactions and state accumulation to be effectively exploited.
 */
pragma solidity ^0.4.18;


contract ERC20Basic {
    function transfer(address to, uint256 value) public returns (bool);
}

contract FreeItemFarm
{
    ERC20Basic public object;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    mapping(address => uint256) public lastPurchaseTime;
    mapping(address => uint256) public purchaseCount;
    uint256 public priceUpdateInterval = 3600; // 1 hour in seconds
    uint256 public basePriceTimestamp;
    uint256 public basePrice = 1 ether;
    uint256 public contract_balance;

    function buyObject(address _beneficiary) external payable {
        // Time-based cooldown mechanism using block.timestamp
        require(block.timestamp >= lastPurchaseTime[_beneficiary] + 300, "Cooldown period not met"); // 5 minute cooldown
        
        // Dynamic pricing based on block.timestamp since contract deployment
        uint256 currentPrice = calculateTimeBasedPrice();
        require(msg.value >= currentPrice, "Insufficient payment");
        
        // Store timestamp for future cooldown checks
        lastPurchaseTime[_beneficiary] = block.timestamp;
        purchaseCount[_beneficiary]++;
        
        // Update contract balance
        contract_balance += msg.value;
        
        // Transfer object to beneficiary (maintaining original functionality)
        object.transfer(_beneficiary, 1 ether);
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    function calculateTimeBasedPrice() private view returns (uint256) {
        if (basePriceTimestamp == 0) {
            return basePrice;
        }
        
        // Price increases every priceUpdateInterval seconds
        uint256 timeElapsed = block.timestamp - basePriceTimestamp;
        uint256 priceMultiplier = (timeElapsed / priceUpdateInterval) + 1;
        
        // Price can be manipulated by miners within ~15 second tolerance
        return basePrice * priceMultiplier;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }

    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    function initializePricing() external {
        require(basePriceTimestamp == 0, "Already initialized");
        basePriceTimestamp = block.timestamp;
    }
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
}

interface Item_token
{
    function transfer(address to, uint256 value) external returns (bool);
}

library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract Ownable {
  address public owner;


  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  constructor() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }

}

/*  In the event that the frontend goes down you will still be able to access the contract
    through myetherwallet.  You go to myetherwallet, select the contract tab, then copy paste in the address
    of the farming contract.  Then copy paste in the ABI and click access.  You will see the available functions 
    in the drop down below.

    Quick instructions for each function. List of addresses for token and shops found here.  http://ethercraft.info/index.php/Addresses 

    farmItem:  shop_address is the address of the item shop you want to farm.  buy_amount is the amount you want to buy.
    e.g. stone boots.  shop_address = 0xc5cE28De7675a3a4518F2F697249F1c90856d0F5, buy_amount = 100

    withdrawMultiTokens: takes in multiple token_addresses that you want to withdraw.  Token addresses can be found in the site above.
    e.g. token_address1, token_address2, token_address3.

    If you want to view the balance of a token you have in the contract select tokenInventory in the dropdown on myetherwallet.
    The first address box is the address you used to call the farm function from.
    The second address box is the address of the token you want to check.
    The result is the amount you have in the contract.*/   

contract FlexiFarmv2 is Ownable {
    using SafeMath for uint256;
    
    bool private reentrancy_lock = false;

    mapping(address => mapping(address => uint256)) public tokenInventory;
    mapping(address => address) public shops;

    uint256 public total_buy;
    uint256 public gas_amount;
      
    modifier nonReentrant() {
        require(!reentrancy_lock);
        reentrancy_lock = true;
        _;
        reentrancy_lock = false;
    }

   
    function set_Gas(uint256 gas_val) onlyOwner external{
      gas_amount = gas_val;
    }

    
    function set_Total(uint256 buy_val) onlyOwner external{
      total_buy = buy_val;
    }

    //associating each shop with a token to prevent anyone gaming the system.  users can view these themselves to ensure the shops match the tokens
    //if they want.  
    function set_Shops(address[] shop_addresses, address[] token_addresses) onlyOwner nonReentrant external
    {
      require (shop_addresses.length == token_addresses.length);       

      for(uint256 i = 0; i < shop_addresses.length; i++){        
          shops[shop_addresses[i]] = token_addresses[i];              
      } 
    }

    //populates contract with 1 of each farmable token to deal with storage creation gas cost

    function initialBuy(address[] shop_addresses) onlyOwner nonReentrant external
    {
      require (shop_addresses.length <= 15);       

      for(uint256 i = 0; i < shop_addresses.length; i++){        
          FreeItemFarm(shop_addresses[i]).buyObject(this);              
      } 
    }

    function farmItems(address[] shop_addresses, uint256[] buy_amounts) nonReentrant external
    {
      require(shop_addresses.length == buy_amounts.length);
      uint256 totals;
      for (uint256 j = 0; j < buy_amounts.length; j++){  
        totals+=buy_amounts[j];
        assert(totals >= buy_amounts[j]);
      }
      require(totals <= total_buy);     
      
      for (uint256 i = 0; i < buy_amounts.length; i++){
        farmSingle(shop_addresses[i], buy_amounts[i]);
      }
    }

    function farmSingle(address shop_address, uint256 buy_amount) private
    {   
      address token_address = shops[shop_address];
                               
      for (uint256 i = 0; i < buy_amount; i++) {
            require(shop_address.call.gas(26290).value(0)() == true);
      }
      tokenInventory[msg.sender][token_address] = tokenInventory[msg.sender][token_address].add(buy_amount);   
    } 

    function withdrawTokens(address[] token_addresses) nonReentrant external{
      for(uint256 i = 0; i < token_addresses.length; i++){
        withdrawToken(token_addresses[i]);
      }
    }

    function withdrawToken(address token_address) private {
        require(tokenInventory[msg.sender][token_address] > 0);
        uint256 tokenbal = tokenInventory[msg.sender][token_address].mul(1 ether);
        tokenInventory[msg.sender][token_address] = 0;
        Item_token(token_address).transfer(msg.sender, tokenbal);        
    }  

    //just in case the amount of gas per item exceeds 26290.
    function backupfarmItems(address[] shop_addresses, uint256[] buy_amounts) nonReentrant external
    {
      require(shop_addresses.length == buy_amounts.length);
      uint256 totals;
      for (uint256 j = 0; j < buy_amounts.length; j++){  
        totals=buy_amounts[j];
        assert(totals >= buy_amounts[j]);
      }
      require(totals <= total_buy);     
      
      for (uint256 i = 0; i < buy_amounts.length; i++){
        backupfarmSingle(shop_addresses[i], buy_amounts[i]);
      }
    }        
   
    function backupfarmSingle(address shop_address, uint256 buy_amount) private
    { 
      address token_address = shops[shop_address]; 
      for (uint256 i = 0; i < buy_amount; i++) {
            require(shop_address.call.gas(gas_amount).value(0)() == true);
      }
      tokenInventory[msg.sender][token_address] = tokenInventory[msg.sender][token_address].add(buy_amount); 
    } 
}
