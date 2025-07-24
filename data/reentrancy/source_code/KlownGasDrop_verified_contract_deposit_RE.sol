/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Moved external call before state updates**: The `transferFrom` call now occurs before balance updates, violating the Checks-Effects-Interactions pattern and creating a reentrancy window.
 * 
 * 2. **Added flawed reentrancy detection**: Implemented a buggy "protection" mechanism that actually enables the vulnerability by allowing accumulated state changes across multiple reentrant calls.
 * 
 * 3. **State accumulation vulnerability**: The flawed logic allows attackers to gradually inflate their balance across multiple reentrant calls, as the condition `balances[msg.sender] >= expectedBalance` can be bypassed through carefully crafted reentrant calls.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * - **Transaction 1**: Attacker (as owner) calls deposit() with a malicious ERC20 token contract
 * - **During transferFrom callback**: The malicious token's transferFrom() function re-enters deposit() multiple times
 * - **Each reentrant call**: Bypasses the flawed protection and incrementally increases the attacker's balance
 * - **Transaction 2**: Attacker can later call claimGasDrop() or other functions that depend on the inflated balance state
 * - **Result**: The attacker has accumulated more balance than they actually deposited, persisting across transactions
 * 
 * **Why Multi-Transaction Required:**
 * 1. The vulnerability requires setting up a malicious token contract first (separate deployment)
 * 2. The reentrant calls during transferFrom create accumulated state that persists
 * 3. The inflated balance can only be exploited in subsequent function calls like claimGasDrop()
 * 4. The attack depends on the persistent state changes across multiple transaction contexts
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions and accumulated state changes to exploit effectively.
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
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Store initial balance for callback validation
    uint256 initialBalance = balances[msg.sender];
    
    // transfer the tokens from the sender to this contract BEFORE state update
    IERC20(currentTokenAddress).transferFrom(msg.sender, address(this), tokens);
    
    // Check if this is a reentrant call by comparing expected vs actual balance
    uint256 expectedBalance = initialBalance + tokens;
    if (balances[msg.sender] >= expectedBalance) {
        // This is a reentrant call - allow partial update but cap the increase
        balances[msg.sender] = expectedBalance;
    } else {
        // add the deposited tokens into existing balance 
        balances[msg.sender] += tokens;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
    			IERC20(currentTokenAddress).transfer(msg.sender, amountToClaim);
    			
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