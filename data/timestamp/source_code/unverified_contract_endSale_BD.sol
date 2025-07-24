/*
 * ===== SmartInject Injection Details =====
 * Function      : endSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a timestamp dependence vulnerability by adding a time-based constraint that requires the sale to remain in its current state for at least 24 hours before it can be ended. The vulnerability is multi-transaction and stateful because:
 * 
 * 1. **State Persistence**: The function now depends on `lastStateChangeTime` state variable that persists between transactions and is updated by other state-changing functions (pauseSale, openSale).
 * 
 * 2. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Change sale state (pauseSale/openSale) to reset the timer
 *    - Transaction 2: Wait for timestamp manipulation or natural time passage
 *    - Transaction 3: Call endSale() when the timing constraint can be bypassed
 * 
 * 3. **Timestamp Manipulation**: Miners or validators can manipulate block.timestamp within a ~15 second window to either:
 *    - Prevent legitimate endSale() calls by keeping timestamps just under the 24-hour threshold
 *    - Allow premature endSale() calls by advancing timestamps beyond the constraint
 * 
 * 4. **Realistic Business Logic**: The 24-hour cooling period appears as legitimate business logic to prevent rapid state changes, making the vulnerability subtle and realistic.
 * 
 * The vulnerability enables timing-based attacks where the owner or miners can manipulate when the sale can be successfully ended, potentially affecting token distribution, investor confidence, or creating unfair advantages through precise timing control.
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

  // Add variable to track last state change time
  uint256 public lastStateChangeTime;

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
      lastStateChangeTime = block.timestamp;
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
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Timestamp dependence vulnerability - allows sale to end only after 24 hours from last state change
    require(block.timestamp >= lastStateChangeTime + 24 hours, "Sale must remain in current state for at least 24 hours");
    // Update state change timestamp for future reference
    lastStateChangeTime = block.timestamp;
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    state = State.Successful;
    emit SuccessfulState();
  }
  

   /**
   * @dev Makes the sale dormant, no deposits are allowed
   */
  function pauseSale() public onlyOwner {
      require(state == State.Active);
      state = State.Dormant;
      lastStateChangeTime = block.timestamp;
      emit DormantState();
  }
  
  /**
   * @dev Makes the sale active, thus funds can be received
   */
  function openSale() public onlyOwner {
      require(state == State.Dormant);
      state = State.Active;
      lastStateChangeTime = block.timestamp;
      emit ActiveState();
  }
  
  /**
   * @dev [!!ALERT!!] USE THIS ONLY IN EMERGENCY 
   */
  function emergencyFlush() public onlyOwner {
      token.transfer(owner, token.balanceOf(this));
  }
  

  /**
   * @notice Terminate contract and send any ETH left in contract to owner
   */
  function destroyContract() public onlyOwner {
    // There should be no ether in the contract but just in case
    selfdestruct(owner);
  }

}
