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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before updating balances. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added external call `_to.call()` to notify recipient contracts before balance updates
 * 2. Used `_to.code.length > 0` to check if recipient is a contract (realistic pattern)
 * 3. Called a hypothetical `onTokenReceived` function on the recipient contract
 * 4. Placed this external call BEFORE the critical balance updates
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker deploys malicious contract with `onTokenReceived` function
 * Transaction 2: Victim transfers tokens to malicious contract
 * - The malicious contract's `onTokenReceived` function is called
 * - At this point, balances haven't been updated yet (sender still has tokens)
 * - The malicious contract can re-enter `transfer()` to send tokens elsewhere
 * - This creates a window where the same tokens can be transferred multiple times
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **Setup Phase**: Attacker must first deploy and configure the malicious contract
 * 2. **State Accumulation**: The vulnerability exploits the temporary inconsistent state between external call and balance update
 * 3. **Repeated Exploitation**: Multiple calls to transfer() are needed to drain significant funds
 * 4. **Realistic Exploitation**: Real-world attacks often involve multiple transactions to avoid detection and maximize profit
 * 
 * The vulnerability is subtle and realistic, as token notification patterns are common in production contracts for backwards compatibility and integration with DeFi protocols.
 */
pragma solidity ^0.4.10;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract PointlessICOExample {
    address owner = msg.sender;

    bool public purchasingAllowed = false;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;
    uint256 public totalBonusTokensIssued = 0;

    uint256 public totalSupply = 0;

    function name() constant returns (string) { return "Pointless ICO Example"; }
    function symbol() constant returns (string) { return "PIE"; }
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
            // Notify recipient before updating balances (vulnerable pattern)
            if (isContract(_to)) {
                bool notificationResult = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
                // Continue regardless of notification result for backwards compatibility
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            Transfer(msg.sender, _to, _value);
            return true;
        } else { return false; }
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
        } else { return false; }
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

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

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
        return (totalContribution, totalSupply, totalBonusTokensIssued, purchasingAllowed);
    }

    function() payable {
        if (!purchasingAllowed) { throw; }
        
        if (msg.value == 0) { return; }

        owner.transfer(msg.value);
        totalContribution += msg.value;

        uint256 tokensIssued = (msg.value * 100);

        if (msg.value >= 10 finney) {
            tokensIssued += totalContribution;

            bytes20 bonusHash = ripemd160(block.coinbase, block.number, block.timestamp);
            if (bonusHash[0] == 0) {
                uint8 bonusMultiplier =
                    (((bonusHash[1] & 0x01) != 0) ? 1 : 0) + (((bonusHash[1] & 0x02) != 0) ? 1 : 0) +
                    (((bonusHash[1] & 0x04) != 0) ? 1 : 0) + (((bonusHash[1] & 0x08) != 0) ? 1 : 0) +
                    (((bonusHash[1] & 0x10) != 0) ? 1 : 0) + (((bonusHash[1] & 0x20) != 0) ? 1 : 0) +
                    (((bonusHash[1] & 0x40) != 0) ? 1 : 0) + (((bonusHash[1] & 0x80) != 0) ? 1 : 0);
                
                uint256 bonusTokensIssued = (msg.value * 100) * bonusMultiplier;
                tokensIssued += bonusTokensIssued;

                totalBonusTokensIssued += bonusTokensIssued;
            }
        }

        totalSupply += tokensIssued;
        balances[msg.sender] += tokensIssued;
        
        Transfer(address(this), msg.sender, tokensIssued);
    }

    // Helper function for contract detection in pre-0.5.0.
    function isContract(address _addr) internal constant returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
