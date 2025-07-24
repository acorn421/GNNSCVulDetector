/*
 * ===== SmartInject Injection Details =====
 * Function      : claimGasDrop
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by reordering the external call and state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. **Preserved External Call Position**: The `IERC20(currentTokenAddress).transfer(msg.sender, amountToClaim)` call remains in the same position but now occurs before the critical state updates
 * 2. **Moved State Updates After External Call**: The `receivers[msg.sender] = true` assignment is now placed AFTER the external transfer call, creating a reentrancy window
 * 3. **Maintained Function Logic**: All original functionality is preserved - the function still performs balance checks, transfers tokens, and updates state variables
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * This vulnerability requires a multi-transaction attack pattern:
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker calls `claimGasDrop()` from their malicious contract
 * - Function checks `receivers[msg.sender] != true` (passes)
 * - Function checks `amountToClaim <= balances[whoSent]` (passes)
 * - Function deducts `balances[whoSent] -= amountToClaim`
 * - Function calls `IERC20(currentTokenAddress).transfer(msg.sender, amountToClaim)`
 * - **Critical Window**: At this point, the transfer has occurred but `receivers[msg.sender]` is still false
 * - The malicious contract's `receive()` or `fallback()` function is triggered by the token transfer
 * 
 * **Transaction 2 (Reentrancy Exploitation):**
 * - From within the token transfer callback, the attacker can call `claimGasDrop()` again
 * - The check `receivers[msg.sender] != true` still passes because the state wasn't updated yet
 * - The attacker can potentially drain more tokens before the original call completes
 * - This creates a multi-transaction reentrancy where the vulnerability spans across the callback transaction
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability requires the external call to trigger a callback in the attacker's contract
 * - The callback represents a separate transaction context where the attacker can re-enter
 * - The inconsistent state (transfer completed but receivers mapping not updated) persists across these transaction boundaries
 * - The attacker needs multiple calls to fully exploit the vulnerability - the initial call to trigger the transfer, and the reentrant call(s) to exploit the inconsistent state
 * 
 * **Realistic Nature:**
 * This pattern is realistic because:
 * 1. It's a subtle violation of the Checks-Effects-Interactions pattern
 * 2. The code appears to follow good practices (checking conditions first, then executing)
 * 3. The vulnerability only becomes apparent when considering the multi-transaction nature of external calls
 * 4. Similar patterns have been seen in real-world smart contract vulnerabilities
 */
pragma solidity ^0.4.17;
//Zep
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}




contract KlownGasDrop {


//receivers
    mapping(address => bool) public receivers;
// token balances
    mapping ( address => uint256 ) public balances;
	//amount per receiver (with decimals)
	uint256 amountToClaim = 50000000;
	uint256 public totalSent = 0;
	
	address  _owner;
	address  whoSent;
	uint256 dappBalance;

//debugging breakpoints, quick and easy 
    uint public brpt = 0;
    uint public brpt1 = 0;

    IERC20 currentToken ;


//modifiers	
	modifier onlyOwner() {
      require(msg.sender == _owner);
      _;
  }
    /// Create new - constructor
     function  KlownGasDrop() public {
		_owner = msg.sender;
		dappBalance = 0;
    }

//address of token contract, not token sender!    
	address currentTokenAddress = 0xc97a5cdf41bafd51c8dbe82270097e704d748b92;


    //deposit
      function deposit(uint tokens) public onlyOwner {


    // add the deposited tokens into existing balance 
    balances[msg.sender]+= tokens;

    // transfer the tokens from the sender to this contract
    IERC20(currentTokenAddress).transferFrom(msg.sender, address(this), tokens);
    whoSent = msg.sender;
    
  }

function hasReceived(address received)  internal  view returns(bool)
{
    bool result = false;
    if(receivers[received] == true)
        result = true;
    
    return result;
}

uint256 temp = 0;
 /// claim gas drop amount (only once per address)
    function claimGasDrop() public returns(bool) {



		//have they already receivered?
        if(receivers[msg.sender] != true)
	    {

    	    //brpt = 1;
    		if(amountToClaim <= balances[whoSent])
    		{
    		    //brpt = 2; 
    		    balances[whoSent] -= amountToClaim;
    			//brpt = 3;
    			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    			
    			// External call moved before critical state updates
    			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    			IERC20(currentTokenAddress).transfer(msg.sender, amountToClaim);
    			
    			// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    			// State updates moved after external call - creates reentrancy window
    			// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    			receivers[msg.sender] = true;
    			totalSent += amountToClaim;
    			
    			//brpt = 4;
    			
    			
    		}

	    }
		

	   
    }


 //which currentToken is used here?
  function setCurrentToken(address currentTokenContract) external onlyOwner {
        currentTokenAddress = currentTokenContract;
        currentToken = IERC20(currentTokenContract);
        dappBalance = currentToken.balanceOf(address(this));
      
  }



 //set amount per gas claim (amount each address will receive)
  function setGasClaim(uint256 amount) external onlyOwner {
    
      amountToClaim = amount;
      
  }
//get amount per gas claim (amount each address will receive)
  function getGasClaimAmount()  public view returns (uint256)  {
    
      return amountToClaim;
      
  }
  
  


}