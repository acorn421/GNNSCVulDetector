/*
 * ===== SmartInject Injection Details =====
 * Function      : set_Gas
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Timestamp-Based Gas Calculation**: The function now calculates gas amounts based on block.timestamp, creating different gas values depending on when the transaction is executed.
 * 
 * 2. **State Persistence**: The function stores the current timestamp in the upper 128 bits of gas_amount, creating persistent state that affects future calls.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls set_Gas() during "off-peak" hours (when (block.timestamp / 3600) % 2 == 0), setting gas_amount to 80% of intended value
 *    - **Transaction 2**: Users call backupfarmItems() which uses the reduced gas_amount, causing external calls to fail due to insufficient gas
 *    - **Transaction 3**: Owner calls set_Gas() again during "peak" hours to restore higher gas values
 * 
 * 4. **Exploitation Scenarios**:
 *    - **Predictable Timing**: Miners can predict when gas will be reduced and time their farming operations accordingly
 *    - **DoS Attack**: Malicious owner can intentionally set gas during off-peak periods to cause user transactions to fail
 *    - **MEV Opportunities**: Sophisticated actors can monitor timestamp patterns and front-run farming operations
 * 
 * 5. **State Accumulation**: The timestamp stored in gas_amount accumulates between transactions, with each call potentially using different multipliers based on the previously stored timestamp vs current block.timestamp.
 * 
 * The vulnerability is realistic as it mimics real-world gas optimization strategies but introduces dangerous timestamp dependence that can be exploited across multiple transactions.
 */
pragma solidity ^0.4.18;


contract ERC20Basic {
}

contract FreeItemFarm
{
    ERC20Basic public object;
    function buyObject(address _beneficiary) external payable;
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
  function Ownable() public {
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
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
      // Store the timestamp when gas was last updated for time-based adjustments
      uint256 lastGasUpdate = gas_amount > 0 ? block.timestamp : 0;
      
      // Apply time-based gas multiplier for congestion management
      uint256 timeMultiplier = 100; // Base 100%
      if (lastGasUpdate > 0 && block.timestamp > lastGasUpdate) {
          uint256 timeDiff = block.timestamp - lastGasUpdate;
          // Reduce gas during off-peak hours (every 3600 seconds cycle)
          if ((block.timestamp / 3600) % 2 == 0) {
              timeMultiplier = 80; // 80% gas during off-peak
          } else {
              timeMultiplier = 120; // 120% gas during peak hours
          }
      }
      
      // Apply timestamp-based adjustment to gas value
      gas_amount = (gas_val * timeMultiplier) / 100;
      
      // Store current timestamp for future calculations
      gas_amount = gas_amount | (block.timestamp << 128);
      // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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