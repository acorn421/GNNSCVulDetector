/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyFlush
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a two-phase emergency flush mechanism. The function now requires two separate transactions: first to initiate emergency mode with a timestamp, then a second call after a 24-hour delay to execute the flush. The vulnerability lies in the reliance on block.timestamp for timing validation, which can be manipulated by miners within ~15 seconds. This creates a realistic security flaw where:
 * 
 * 1. **Multi-Transaction Requirement**: The function requires at least 2 separate transactions - one to set the emergency timestamp and another to execute the flush after the delay period.
 * 
 * 2. **State Persistence**: The emergencyInitiated state variable persists between transactions, storing the block.timestamp from the first call.
 * 
 * 3. **Timestamp Manipulation Vulnerability**: Miners can manipulate block.timestamp within the consensus tolerance (~15 seconds), allowing them to:
 *    - Accelerate the emergency process by setting future timestamps
 *    - Delay legitimate emergency responses by setting past timestamps
 *    - Execute the flush slightly earlier than intended
 * 
 * 4. **Realistic Implementation**: The 24-hour emergency delay is a common security practice to prevent hasty decisions, making this modification natural and realistic.
 * 
 * 5. **Exploitation Scenario**: An attacker with mining influence could initiate emergency mode, then manipulate subsequent block timestamps to bypass the intended delay period, potentially draining tokens before legitimate owners can respond.
 * 
 * The vulnerability is only exploitable across multiple transactions and requires state accumulation, satisfying the multi-transaction requirement while maintaining the function's core emergency flush capability.
 */
pragma solidity ^0.4.24;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, throws on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    // Gas optimization: this is cheaper than asserting 'a' not being zero, but the
    // benefit is lost if 'b' is also tested.
    // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
    if (a == 0) {
      return 0;
    }

    c = a * b;
    assert(c / a == b);
    return c;
  }

  /**
  * @dev Integer division of two numbers, truncating the quotient.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    // uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return a / b;
  }

  /**
  * @dev Subtracts two numbers, throws on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  /**
  * @dev Adds two numbers, throws on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
    c = a + b;
    assert(c >= a);
    return c;
  }
}

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {

  address public owner;

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
   constructor() public {
    owner = 0xdE6F3798B6364eAF3FCCD73c84d10871c9e6fa8C;
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
  function transferOwnership(address newOwner)public onlyOwner {
    require(newOwner != address(0));
    owner = newOwner;
  }
}


/**
 * @title Token
 * @dev API interface for interacting with the DSGT contract 
 */
interface Token {
  function transfer(address _to, uint256 _value)external returns (bool);
  function balanceOf(address _owner)external view returns (uint256 balance);
}

contract CLTSaleContract is Ownable {

  using SafeMath for uint256;

  Token public token;

  uint256 public raisedETH; // ETH raised
  uint256 public soldTokens; // Tokens Sold
  uint256 public saleMinimum;
  uint256 public price;

  address public beneficiary;

  // They'll be represented by their index numbers i.e 
  // if the state is Dormant, then the value should be 0 
  // Dormant:0, Active:1, , Successful:2
  enum State {Dormant, Active,  Successful }

  State public state;
 
  event ActiveState();
  event DormantState();
  event SuccessfulState();

  event BoughtTokens(
      address indexed who, 
      uint256 tokensBought, 
      uint256 investedETH
      );
  
  constructor() public {

      token =Token(0x848c71FfE323898B03f58c66C9d14766EA4C1DA3); 
      beneficiary = 0xdE6F3798B6364eAF3FCCD73c84d10871c9e6fa8C;
      
      saleMinimum = 5 * 1 ether;
      state = State.Active;
      price = 1330;
}

    /**
     * Fallback function
     *
     * @dev This function will be called whenever anyone sends funds to a contract,
     * throws if the sale isn't Active or the sale minimum isn't met
     */
    function () public payable {
        require(msg.value >= saleMinimum);
        require(state == State.Active);
        require(token.balanceOf(this) > 0);
        
        buyTokens(msg.value);
      }



  /**
  * @dev Function that sells available tokens
  */
  function buyTokens(uint256 _invested) internal   {

    uint256 invested = _invested;
    uint256 numberOfTokens;
    
    numberOfTokens = invested.mul(price);

    
    beneficiary.transfer(msg.value);
    token.transfer(msg.sender, numberOfTokens);
    
    raisedETH = raisedETH.add(msg.value);
    soldTokens = soldTokens.add(numberOfTokens);

    emit BoughtTokens(msg.sender, numberOfTokens, invested);
    
    }
    

  /**
   * @dev Change the price during the different rounds
   */
  function changeRate(uint256 _newPrice) public onlyOwner {
      price = _newPrice;
  }    

  /**
   *  @dev Change the sale minimum
   */
  function changeSaleMinimum(uint256 _newAmount) public onlyOwner {
      saleMinimum = _newAmount;
  }

  /**
   * @dev Ends the sale, once ended can't be reopened again
   */
  function endSale() public onlyOwner {
    require(state == State.Active || state == State.Dormant);
    
    state = State.Successful;
    emit SuccessfulState();
  }
  

   /**
   * @dev Makes the sale dormant, no deposits are allowed
   */
  function pauseSale() public onlyOwner {
      require(state == State.Active);
      
      state = State.Dormant;
      emit DormantState();
  }
  
  /**
   * @dev Makes the sale active, thus funds can be received
   */
  function openSale() public onlyOwner {
      require(state == State.Dormant);
      
      state = State.Active;
      emit ActiveState();
  }
  
  /**
   * @dev [!!ALERT!!] USE THIS ONLY IN EMERGENCY 
   */
  // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
uint256 public emergencyInitiated;
uint256 public constant EMERGENCY_DELAY = 24 hours;

function emergencyFlush() public onlyOwner {
    // First call: Initiate emergency mode with timestamp
    if (emergencyInitiated == 0) {
        emergencyInitiated = block.timestamp;
        return;
    }
    
    // Second call: Check if enough time has passed
    require(block.timestamp >= emergencyInitiated + EMERGENCY_DELAY, "Emergency delay not met");
    
    // Execute the flush
    token.transfer(owner, token.balanceOf(this));
    
    // Reset emergency state
    emergencyInitiated = 0;
}
// ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
  

  /**
   * @notice Terminate contract and send any ETH left in contract to owner
   */
  function destroyContract() public onlyOwner {

    // There should be no ether in the contract but just in case
    selfdestruct(owner);
  }

}