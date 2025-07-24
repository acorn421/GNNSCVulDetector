/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Reordered State Updates**: Moved `allowance[src][msg.sender] -= wad;` to occur AFTER the external call, creating a reentrancy window
 * 2. **Added External Call**: Introduced a call to `dst.call()` with `onTokenReceived` signature if the destination is a contract
 * 3. **State Inconsistency Window**: The external call happens after balance updates but before allowance updates, creating exploitable state inconsistency
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Attacker contract gets approved for large allowance (e.g., 1000 tokens) from victim
 * - Victim has sufficient balance (e.g., 1000 tokens)
 * 
 * **Exploitation Phase (Transaction 2):**
 * - Attacker calls `transferFrom(victim, attackerContract, 500)`
 * - Function updates balances: `balanceOf[victim] -= 500`, `balanceOf[attackerContract] += 500`
 * - External call to `attackerContract.onTokenReceived()` is triggered
 * - **CRITICAL**: At this point, allowance has NOT been updated yet, still shows 1000
 * - Inside `onTokenReceived`, attacker calls `transferFrom(victim, attackerContract, 500)` again
 * - Second call succeeds because allowance[victim][attacker] still shows 1000 (not yet decremented)
 * - This creates a loop where attacker can drain more tokens than their allowance permits
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The allowance state persists between the initial call and the reentrancy call
 * 2. **External Call Dependency**: The vulnerability only triggers when dst is a contract that can execute code
 * 3. **Sequence Dependency**: Requires the specific sequence of balance update → external call → allowance update
 * 4. **Accumulated State Exploitation**: Each reentrancy call exploits the accumulated state inconsistency
 * 
 * **State Exploitation Pattern:**
 * - Transaction 1: Setup allowance
 * - Transaction 2: Initial transferFrom call creates state inconsistency window
 * - Within Transaction 2: Reentrancy exploits the inconsistent state multiple times
 * - Result: Attacker transfers more tokens than their allowance should permit
 * 
 * This creates a realistic, stateful vulnerability that requires multiple function calls and exploits the persistent state between the external call and the final allowance update.
 */
pragma solidity ^0.4.25;

contract MYFIE {
    string public name = "Monetize Your Selfie";      //  token name
    string public symbol = "MYFIE";           //  token symbol
    string public version = "2.0";
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 110000000000000000;
    uint256 public MaxSupply = 0;
    bool public stopped = true;

    //000 000 000 000 000 000
    address owner = 0x48850F503412d8A6e3d63541F0e225f04b13a544;
    address minter = 0x47c803871c99EC7180E50dcDA989320871FcBfEE;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isMinter {
        assert(minter == msg.sender);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor () public {
        MaxSupply = 1154000000000000000;
        balanceOf[owner] = totalSupply;
        emit Transfer(0x0, owner, totalSupply);
    }

    function changeOwner(address _newaddress) isOwner public {
        owner = _newaddress;
    }

    function changeMinter(address _new_mint_address) isOwner public {
        minter = _new_mint_address;
    }

    function airdropMinting(address[] _to_list, uint[] _values) isMinter public {
        require(_to_list.length == _values.length);
        for (uint i = 0; i < _to_list.length; i++) {
            mintToken(_to_list[i], _values[i]);
        }
    }

    function setMaxSupply(uint256 maxsupply_amount) isOwner public {
      MaxSupply = maxsupply_amount;
    }

    function mintToken(address target, uint256 mintedAmount) isMinter public {
      require(MaxSupply > totalSupply);
      balanceOf[target] += mintedAmount;
      totalSupply += mintedAmount;
      emit Transfer(0, this, mintedAmount);
      emit Transfer(this, target, mintedAmount);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool success) {
        require(balanceOf[src] >= wad);
        require(allowance[src][msg.sender] >= wad);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update balances first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it's a contract address
        uint length;
        assembly {
            length := extcodesize(dst)
        }
        if (length > 0) {
            bytes memory data = abi.encodeWithSignature("onTokenReceived(address,address,uint256)", src, msg.sender, wad);
            // Typecast dst to address to address(this) to match (bool,) return - see Solidity 0.4
            // call returns (bool, bytes), ignore second
            //solium-disable-next-line security/no-low-level-calls
            if (!dst.call(data)) {
                // Continue execution regardless of call result
            }
        }
        
        // Update allowance after external call - VULNERABILITY: Creates reentrancy window
        allowance[src][msg.sender] -= wad;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(src, dst, wad);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
