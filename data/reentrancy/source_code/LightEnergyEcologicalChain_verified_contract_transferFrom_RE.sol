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
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced a "transfer notification hook" that calls `onTransferReceived()` on the recipient contract if it's a contract address (checked via `_to.code.length > 0`).
 * 
 * 2. **Moved State Updates After External Call**: All critical state modifications (`balances[_from]`, `balances[_to]`, `allowed[_from][msg.sender]`) now occur AFTER the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 3. **Realistic Integration**: The notification hook appears as a legitimate feature that could be found in production code for notifying recipient contracts of incoming transfers.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker deploys a malicious contract that implements `onTransferReceived()`
 * - Attacker calls `approve()` to give themselves a large allowance from victim's account
 * - Attacker ensures victim has sufficient balance in their account
 * 
 * **Transaction 2 - Exploitation Phase:**
 * - Attacker calls `transferFrom()` to transfer tokens from victim to their malicious contract
 * - When the external call to `onTransferReceived()` is made, the malicious contract's callback is triggered
 * - **Critical**: At this point, the state hasn't been updated yet - balances and allowances are still in their pre-transfer state
 * - The malicious contract can now make recursive calls to `transferFrom()` using the same allowance multiple times
 * - Each recursive call sees the original balance/allowance values, allowing unlimited draining
 * 
 * **Why Multi-Transaction is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability depends on having pre-existing allowances set up in previous transactions via `approve()` calls.
 * 
 * 2. **Persistent State Dependency**: The exploit relies on the persistent state of `balances` and `allowed` mappings that were established in prior transactions.
 * 
 * 3. **Sequential Exploitation**: The attacker must first establish the necessary allowances and balances through legitimate transactions before the reentrancy can be exploited.
 * 
 * 4. **Cannot Be Atomic**: The vulnerability cannot be exploited in a single transaction because it requires the pre-existing state setup (allowances) that must be established beforehand.
 * 
 * **Exploitation Flow:**
 * 1. **Setup Transactions**: Victim approves attacker's allowance, attacker deploys malicious contract
 * 2. **Trigger Transaction**: Attacker calls `transferFrom()` targeting their malicious contract
 * 3. **Reentrancy Chain**: Malicious contract recursively calls `transferFrom()` multiple times before original state updates occur
 * 4. **State Corruption**: Multiple transfers occur using the same allowance, draining victim's balance
 * 
 * This creates a stateful, multi-transaction vulnerability where the exploit depends on accumulated state from previous transactions and cannot be executed atomically.
 */
pragma solidity ^0.4.23;

contract LightEnergyEcologicalChain // @HD.ChainFull.Co.Ltd
{
    address public admin_address = 0x5d9CC08eb47aE51069ED64BFAfBcF3a8e531f881;
    address public account_address = 0x5d9CC08eb47aE51069ED64BFAfBcF3a8e531f881;
    mapping(address => uint256) balances;
    string public name = "Light Energy Ecological Chain";
    string public symbol = "LEE";
    uint8 public decimals = 18;
    uint256 initSupply = 570000000;
    uint256 public totalSupply = 0;
    constructor() 
    payable 
    public
    {
        totalSupply = mul(initSupply, 10**uint256(decimals));
        balances[account_address] = totalSupply;
    }

    function balanceOf( address _addr ) public view returns ( uint )
    {
        return balances[_addr];
    }

    event Transfer(
        address indexed from, 
        address indexed to, 
        uint256 value
    ); 

    function transfer(
        address _to, 
        uint256 _value
    ) 
    public 
    returns (bool) 
    {
        require(_to != address(0));
        require(_value <= balances[msg.sender]);

        balances[msg.sender] = sub(balances[msg.sender],_value);

        balances[_to] = add(balances[_to], _value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    mapping (address => mapping (address => uint256)) internal allowed;
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    )
    public
    returns (bool)
    {
        require(_to != address(0));
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Transfer notification hook - allows recipient to be notified of incoming transfer
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            // Call recipient contract to notify of incoming transfer
            // We have to use low-level call (address(_to).call), but keep as close as possible
            // The next line is as intended in newer Solidity, but for 0.4.x we use 'call' and encode args manually
            // (bool success,) = _to.call(abi.encodeWithSignature...) is not valid in 0.4.23
            bool success = _to.call(
                bytes4(keccak256("onTransferReceived(address,address,uint256)")),
                _from,
                _to,
                _value
            );
            require(success, "Transfer notification failed");
        }
        // Update balances after external call - VULNERABILITY: State changes after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] = sub(balances[_from], _value);
        balances[_to] = add(balances[_to], _value);
        allowed[_from][msg.sender] = sub(allowed[_from][msg.sender], _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(
        address _spender, 
        uint256 _value
    ) 
    public 
    returns (bool) 
    {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(
        address _owner,
        address _spender
    )
    public
    view
    returns (uint256)
    {
        return allowed[_owner][_spender];
    }

    function increaseApproval(
        address _spender,
        uint256 _addedValue
    )
    public
    returns (bool)
    {
        allowed[msg.sender][_spender] = add(allowed[msg.sender][_spender], _addedValue);
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function decreaseApproval(
        address _spender,
        uint256 _subtractedValue
    )
    public
    returns (bool)
    {
        uint256 oldValue = allowed[msg.sender][_spender];

        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } 
        else 
        {
            allowed[msg.sender][_spender] = sub(oldValue, _subtractedValue);
        }
        
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    modifier admin_only()
    {
        require(msg.sender==admin_address);
        _;
    }

    function setAdmin( address new_admin_address ) 
    public 
    admin_only 
    returns (bool)
    {
        require(new_admin_address != address(0));
        admin_address = new_admin_address;
        return true;
    }

    function withDraw()
    public
    admin_only
    {
        require(address(this).balance > 0);
        admin_address.transfer(address(this).balance);
    }

    function () external payable
    {
        
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256 c) 
    {
        if (a == 0) 
        {
            return 0;
        }
        c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) 
    {
        return a / b;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) 
    {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 c) 
    {
        c = a + b;
        assert(c >= a);
        return c;
    }
}
