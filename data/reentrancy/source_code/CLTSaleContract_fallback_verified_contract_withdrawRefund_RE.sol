/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawRefund
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This introduces a multi-transaction reentrancy vulnerability where an attacker must first call requestRefund() to set up the refund amount, then call withdrawRefund() which is vulnerable to reentrancy attacks. The vulnerability persists across transactions through the refundRequests mapping and refundProcessed boolean state. The external call to msg.sender.call.value() happens before state changes, allowing the attacker to re-enter and drain funds. The resetRefundStatus() function allows the attack to be repeated.
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

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    mapping(address => uint256) public refundRequests;
    mapping(address => bool) public refundProcessed;
    
    /**
     * @dev Request a refund for purchased tokens
     * @param _tokenAmount Amount of tokens to refund
     */
    function requestRefund(uint256 _tokenAmount) public {
        require(state == State.Active || state == State.Dormant, "Sale must be active or dormant");
        require(_tokenAmount > 0, "Token amount must be greater than 0");
        require(token.balanceOf(msg.sender) >= _tokenAmount, "Insufficient token balance");
        
        uint256 refundAmount = _tokenAmount.div(price);
        refundRequests[msg.sender] = refundRequests[msg.sender].add(refundAmount);
        
        // Transfer tokens back to contract
        token.transfer(address(this), _tokenAmount);
    }
    
    /**
     * @dev Withdraw requested refund (VULNERABLE TO REENTRANCY)
     */
    function withdrawRefund() public {
        require(refundRequests[msg.sender] > 0, "No refund available");
        require(!refundProcessed[msg.sender], "Refund already processed");
        
        uint256 refundAmount = refundRequests[msg.sender];
        
        // VULNERABILITY: External call before state change
        // This allows reentrancy attack across multiple transactions
        msg.sender.call.value(refundAmount)("");
        
        // State changes after external call - vulnerable to reentrancy
        refundProcessed[msg.sender] = true;
        refundRequests[msg.sender] = 0;
    }
    
    /**
     * @dev Reset refund processing status (allows re-exploitation)
     */
    function resetRefundStatus() public onlyOwner {
        refundProcessed[msg.sender] = false;
    }
    // === END FALLBACK INJECTION ===

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