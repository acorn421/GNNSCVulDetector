/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * **Stateful, Multi-Transaction Reentrancy Vulnerability Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added assembly code to check if the target address contains contract code
 * - Introduced an external call to `target.call(abi.encodeWithSignature("onTokensMinted(uint256)", mintedAmount))` BEFORE state updates
 * - The external call attempts to notify the recipient contract about incoming tokens
 * - Used low-level `call` instead of interface to maintain backward compatibility
 * - State updates (balanceOf and totalSupply) occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * 
 * **Phase 1 - Setup (Transaction 1):**
 * - Owner deploys a malicious contract or the target contract becomes compromised
 * - Malicious contract implements the `onTokensMinted` callback function
 * 
 * **Phase 2 - Initial Exploitation (Transaction 2):**
 * - Owner calls `mintToken(maliciousContract, 1000)`
 * - External call to `maliciousContract.onTokensMinted(1000)` executes
 * - Malicious contract receives control BEFORE state updates occur
 * - During callback, malicious contract can:
 *   - Call other contract functions that depend on current balances
 *   - Interact with external contracts using stale state
 *   - Set up conditions for future exploitation
 * 
 * **Phase 3 - State Accumulation (Transactions 3-N):**
 * - Multiple subsequent calls to `mintToken` for different recipients
 * - Each call creates temporary state inconsistencies during the callback window
 * - Malicious contract can observe and react to these state changes
 * - The vulnerability compounds over multiple transactions as state becomes increasingly inconsistent
 * 
 * **Phase 4 - Final Exploitation (Transaction N+1):**
 * - Malicious contract exploits accumulated state inconsistencies
 * - Can manipulate other contract functions that depend on balances
 * - Potential to drain funds or manipulate token distribution
 * 
 * **3. Why Multi-Transaction Exploitation is Required:**
 * 
 * **State Persistence Requirement:**
 * - The vulnerability depends on the contract's persistent state (balanceOf, totalSupply)
 * - Each transaction modifies this state, creating conditions for future exploitation
 * - Single transaction cannot exploit the full vulnerability as state needs to accumulate
 * 
 * **Sequence Dependency:**
 * - Transaction 1: Sets up malicious contract with callback
 * - Transaction 2+: Each mintToken call creates temporary state inconsistency
 * - Final Transaction: Exploits accumulated inconsistencies
 * 
 * **Cross-Transaction State Observation:**
 * - Malicious contract can observe state changes across multiple transactions
 * - Can build up information about contract behavior and timing
 * - Uses this information to time final exploitation perfectly
 * 
 * **Realistic Attack Vector:**
 * - In real-world scenarios, the owner might be a multi-sig wallet or DAO
 * - Multiple legitimate minting operations provide cover for malicious activities
 * - The vulnerability is subtle and might not be detected until significant value is at risk
 * 
 * This vulnerability is particularly dangerous because it appears to be a helpful feature (notifying recipients) but creates a window for sophisticated multi-transaction attacks that exploit the temporal gap between external calls and state updates.
 */
pragma solidity ^0.4.18;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract Fomo5d {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;
	
	mapping(address=>bool) public frozenAccount;
	uint256 public rate = 20000 ;//1 ether=how many tokens
	uint256 public amount; 
	
	address public owner;
	bool public fundOnContract=true;	
	bool public contractStart=true;	 
	bool public exchangeStart=true;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
	 
	modifier  onlyOwner{
        if(msg.sender != owner){
            revert();
        }else{
            _;
        }
    }

    function transferOwner(address newOwner)  public onlyOwner{
        owner = newOwner;
    }
	 

	 
    function Fomo5d() public payable{
		decimals=18;
        totalSupply = 1000000000 * (10 ** uint256(decimals));  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "Fomo5d";                                   // Set the name for display purposes
        symbol = "F5d";                               // Set the symbol for display purposes
		owner = msg.sender;
		rate=20000;
		fundOnContract=true;
		contractStart=true;
		exchangeStart=true;
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
		if(frozenAccount[_from]){
            revert();
        }
		if(frozenAccount[_to]){
            revert();
        }
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
		if(!contractStart){
			revert();
		}
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
		if(!contractStart){
			revert();
		}
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
		require(_value > 0);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
		if(!contractStart){
			revert();
		}
		require(balanceOf[msg.sender] >= _value);
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
		if(!contractStart){
			revert();
		}
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
		if(!contractStart){
			revert();
		}
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
		require(_value > 0);
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
		Transfer(msg.sender, 0, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public onlyOwner returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
		require(_value> 0); 
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        totalSupply -= _value;                              // Update totalSupply
		Transfer(_from, 0, _value);
        return true;
    }
	
	function () public payable{
		if(!contractStart){
			revert();
		}
        if(frozenAccount[msg.sender]){
            revert();
        }
		amount = uint256(msg.value * rate);
		
		if(balanceOf[msg.sender]+amount<balanceOf[msg.sender]){
			revert();
		}
		if(balanceOf[owner]<amount){
			revert();
		}
		//if(amount>0){
			if(exchangeStart){
				balanceOf[owner] -=amount ;
				balanceOf[msg.sender] +=amount;
				Transfer(owner, msg.sender, amount); //token event
			}
			if(!fundOnContract){
				owner.transfer(msg.value);
			}
		//}
    }

	function transferFund(address target,uint256 _value) public onlyOwner{
		if(frozenAccount[target]){
            revert();
        }
		if(_value<=0){
			revert();
		}
		if(_value>this.balance){
			revert();
		}
		if(target != 0){
			target.transfer(_value);
		}
    }
	
	
	function setFundOnContract(bool _fundOnContract)  public onlyOwner{
            fundOnContract = _fundOnContract;
    }
	
	function setContractStart(bool _contractStart)  public onlyOwner{
            contractStart = _contractStart;
    }
	
	function freezeAccount(address target,bool _bool)  public onlyOwner{
        if(target != 0){
            frozenAccount[target] = _bool;
        }
    }
	function setRate(uint thisRate) public onlyOwner{
	   if(thisRate>=0){
         rate = thisRate;
		}
    }
	
	function mintToken(address target, uint256 mintedAmount) public onlyOwner {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if target is a contract and has a callback function
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(target)
        }
        
        if (codeSize > 0) {
            // Make external call to notify recipient before state updates
            // This creates a reentrancy opportunity if target is malicious
            (bool success, ) = target.call(abi.encodeWithSignature("onTokensMinted(uint256)", mintedAmount));
            // Continue even if call fails to maintain backward compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, owner, mintedAmount);
        Transfer(owner, target, mintedAmount);
    }
	function ownerKill(address target) public onlyOwner {
		selfdestruct(target);
    }
	function withdraw(address target) public onlyOwner {
		target.transfer(this.balance);
    }
	function getBalance() public constant returns(uint) {
		return this.balance;
	}
	function setExchangeStart(bool _exchangeStart)  public onlyOwner{
            exchangeStart = _exchangeStart;
    }
}