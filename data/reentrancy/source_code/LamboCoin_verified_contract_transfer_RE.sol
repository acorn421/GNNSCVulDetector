/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism before state updates. The vulnerability works as follows:
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * 1. **Setup Phase (Transaction 1)**: An attacker deploys a malicious contract that implements the `onTokenReceived(address,uint256)` callback function. This malicious contract is designed to call back into the LamboCoin contract during the callback execution.
 * 
 * 2. **Exploitation Phase (Transaction 2+)**: When legitimate users transfer tokens to the malicious contract address, the transfer function:
 *    - Checks balances and validates the transfer (CEI pattern followed initially)
 *    - Makes an external call to the malicious contract's `onTokenReceived` callback BEFORE updating balances
 *    - During this callback, the malicious contract can re-enter the transfer function
 *    - Since balances haven't been updated yet, the original sender still appears to have their full balance
 *    - The malicious contract can trigger additional transfers, draining more tokens than intended
 * 
 * **Why This Requires Multiple Transactions:**
 * 
 * 1. **State Accumulation**: The malicious contract needs to be deployed and positioned as a recipient in a separate transaction first
 * 2. **Callback Dependency**: The vulnerability only triggers when tokens are transferred TO a contract address, requiring the malicious contract to be in place
 * 3. **Balance Manipulation**: The exploit works by having the malicious contract accumulate tokens from multiple victims over time, with each transfer allowing reentrancy
 * 4. **Persistent Attack Surface**: The malicious contract remains deployed between transactions, maintaining its ability to exploit future transfers
 * 
 * **Technical Details:**
 * - The external call using `_to.call()` happens before `balances[msg.sender] -= _value`
 * - This violates the Checks-Effects-Interactions (CEI) pattern
 * - The malicious contract can reenter during the callback and execute additional transfers
 * - Each successful transfer to the malicious contract compounds the vulnerability
 * - The attack requires the malicious contract to be funded and positioned as a recipient through previous transactions
 */
pragma solidity ^0.4.10;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract LamboCoin {
    address owner = msg.sender;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

	bool public purchasingAllowed = false;
    uint256 public totalContribution = 0;
    uint256 public totalSupply = 0;
	uint256 public maxSupply = 0;

    function name() constant returns (string) { return "LamboCoin"; }
    function symbol() constant returns (string) { return "LBC"; }
    function decimals() constant returns (uint8) { return 18; }
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }

    function transfer(address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (2 * 32) + 4) { throw; }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];

        if (sufficientFunds && !overflowed) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Add external call before state updates for recipient notification
            if (_to != msg.sender) {
                // Check if recipient has a callback interface
                uint256 codeSize;
                assembly {
                    codeSize := extcodesize(_to)
                }
                
                if (codeSize > 0) {
                    // Call recipient's onTokenReceived callback before updating state
                    // This allows reentrancy during the callback execution
                    bool callSuccess = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                    
                    // Continue with transfer regardless of callback success
                    // This preserves the original transfer functionality
                }
            }
            
            // State updates happen after external call - vulnerability window
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _value;
            balances[_to] += _value;

            Transfer(msg.sender, _to, _value);
            return true;
        } else {
			return false;
		}
    }

    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (3 * 32) + 4) { throw; }

        if (_value == 0) { return false; }

        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance <= _value;
        bool sufficientAllowance = allowance <= _value;
        bool overflowed = balances[_to] + _value > balances[_to];

        if (sufficientFunds && sufficientAllowance && !overflowed) {
            balances[_to] += _value;
            balances[_from] -= _value;

            allowed[_from][msg.sender] -= _value;

            Transfer(_from, _to, _value);
            return true;
        } else {
			return false;
		}
    }

    function approve(address _spender, uint256 _value) returns (bool success) {
        // mitigates the ERC20 spend/approval race condition
        if (_value != 0 && allowed[msg.sender][_spender] != 0) { return false; }

        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    function enablePurchasing() {
        if (msg.sender != owner) { throw; }

        purchasingAllowed = true;
    }

    function disablePurchasing() {
        if (msg.sender != owner) { throw; }

        purchasingAllowed = false;
    }

    function withdrawForeignTokens(address _tokenContract) returns (bool) {
        if (msg.sender != owner) { throw; }

        ForeignToken token = ForeignToken(_tokenContract);

        uint256 amount = token.balanceOf(address(this));
        return token.transfer(owner, amount);
    }

    function getStats() constant returns (uint256, uint256, uint256, bool) {
        return (totalContribution, totalSupply, maxSupply, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { throw; }
        if (msg.value == 0) { return; }

		//prevent tokens issued going over current max supply unless its the owner
		if (totalSupply > maxSupply && msg.sender != owner) { throw; }

        owner.transfer(msg.value);

        totalContribution += msg.value;
        uint256 tokensIssued = (msg.value * 100);
		totalSupply += tokensIssued;

		//Allow owner to increase max supply as desired
		if( msg.sender == owner ) {
			maxSupply += (msg.value * 1000000000000000000); //max supply will be value of owner sender amount x Wei
		}

		balances[msg.sender] += tokensIssued;
        Transfer(address(this), msg.sender, tokensIssued);
    }

	event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}