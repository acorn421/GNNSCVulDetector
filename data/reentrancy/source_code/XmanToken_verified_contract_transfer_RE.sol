/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding:
 * 
 * 1. **Pending Transfer System**: Added pendingTransfers mapping and totalPendingTransfers counter to track incomplete transfers
 * 2. **External Call After State Changes**: Added call to recipient's onTokenReceived function after balance updates
 * 3. **Accumulated State**: Failed notifications leave pending transfers in state, creating exploitable conditions across multiple transactions
 * 4. **Multi-Transaction Exploitation Path**: 
 *    - Transaction 1: Malicious contract receives transfer, fails notification deliberately to accumulate pending state
 *    - Transaction 2-N: Attacker can exploit the accumulated pending transfer state by manipulating the notification mechanism
 *    - The vulnerability requires building up sufficient pending transfer state over multiple transactions before exploitation
 * 
 * The vulnerability is multi-transaction because:
 * - Single transaction exploitation is prevented by the external call happening after balance updates
 * - Exploitation requires accumulated pending transfer state from previous failed notifications
 * - The attacker needs multiple transactions to build up exploitable state and then trigger the vulnerability
 * - The pending transfer system creates persistent state that can be manipulated across transaction boundaries
 */
pragma solidity ^0.4.10;

contract ForeignToken {
    function balanceOf(address _owner) constant returns (uint256);
    function transfer(address _to, uint256 _value) returns (bool);
}

contract XmanToken {
    address owner = msg.sender;
    
    bool public purchasingAllowed = false;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    // Added declarations for pendingTransfers and totalPendingTransfers
    mapping(address => mapping(address => uint256)) pendingTransfers;
    uint256 public totalPendingTransfers = 0;

    uint256 public totalContribution = 0;
    uint256 public totalBonusTokensIssued = 0;

    uint256 public totalSupply = 0;

    function name() constant returns (string) { return "XmanToken"; }
    function symbol() constant returns (string) { return "UET"; }
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
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Add pending transfer record for notification system
            pendingTransfers[msg.sender][_to] += _value;
            totalPendingTransfers += _value;
            
            Transfer(msg.sender, _to, _value);
            
            // Notify recipient about the transfer - VULNERABLE: External call after state changes
            if (isContract(_to)) {
                // Call recipient's notification function if it exists
                // Using low-level call in Solidity 0.4.x
                bytes4 sig = bytes4(keccak256("onTokenReceived(address,uint256)"));
                // solium-disable-next-line security/no-low-level-calls
                bool callSuccess = _to.call(sig, msg.sender, _value);
                if (callSuccess) {
                    // On successful notification, clear pending transfer
                    pendingTransfers[msg.sender][_to] -= _value;
                    totalPendingTransfers -= _value;
                } else {
                    // If notification fails, keep pending transfer for retry
                    // This creates accumulated state across multiple transactions
                }
            } else {
                // For EOA recipients, immediately clear pending
                pendingTransfers[msg.sender][_to] -= _value;
                totalPendingTransfers -= _value;
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            return true;
        } else { return false; }
    }
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        // mitigates the ERC20 short address attack
        if(msg.data.length < (3 * 32) + 4) { throw; }

        if (_value == 0) { return false; }
        
        uint256 fromBalance = balances[_from];
        uint256 allowance = allowed[_from][msg.sender];

        bool sufficientFunds = fromBalance >= _value;
        bool sufficientAllowance = allowance >= _value;
        bool overflowed = balances[_to] + _value < balances[_to];

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

    // Helper to determine if an address is a contract in Solidity 0.4.x
    function isContract(address _addr) internal constant returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
