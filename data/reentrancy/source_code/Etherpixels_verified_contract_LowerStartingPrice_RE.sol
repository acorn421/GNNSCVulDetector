/*
 * ===== SmartInject Injection Details =====
 * Function      : LowerStartingPrice
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: The function now calls an external contract (`priceUpdateCallback`) before updating the `starting_price` state variable. This creates a classic reentrancy vulnerability where the external contract can call back into this function.
 * 
 * 2. **State Accumulation Mechanism**: Added `priceChangeCount` and `lastPriceChange` state variables that accumulate across multiple transactions, making the vulnerability multi-transaction dependent.
 * 
 * 3. **Realistic Integration**: The price callback mechanism is a realistic feature that might be found in production DeFi contracts for oracle updates or governance notifications.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker deploys a malicious contract and sets it as the `priceUpdateCallback`
 * - The malicious contract's `onPriceUpdate` function is designed to re-enter `LowerStartingPrice`
 * 
 * **Transaction 2 (Initial Call)**:
 * - Owner calls `LowerStartingPrice(newPrice)` 
 * - Function passes the require check: `newPrice < starting_price`
 * - External call to malicious contract's `onPriceUpdate` occurs
 * - **Critical**: `starting_price` has NOT been updated yet
 * 
 * **Transaction 2 (Reentrancy)**:
 * - Malicious contract calls `LowerStartingPrice(evenLowerPrice)` during the callback
 * - The require check uses the OLD `starting_price` value (not yet updated)
 * - This allows setting prices that would normally be rejected
 * - State accumulation (`priceChangeCount`) gets corrupted across the nested calls
 * 
 * **Why Multi-Transaction Dependent:**
 * - The vulnerability requires the initial setup transaction to install the malicious callback
 * - The exploitation happens during the callback, creating a nested call sequence
 * - The state inconsistency (old `starting_price` vs new `starting_price`) only exists during the multi-call sequence
 * - Single transaction exploitation is impossible without the pre-existing malicious callback setup
 * 
 * **Impact:** An attacker could bypass the price reduction limits and set starting prices lower than intended, potentially affecting the entire game economy and pixel pricing mechanism.
 */
pragma solidity ^0.4.18;

interface IPriceCallback {
    function onPriceUpdate(uint new_price, uint old_price) external;
}

contract usingOwnership {
  address public contract_owner;

  modifier onlyOwner() {
    require(msg.sender == contract_owner);
    _;
  }

  constructor() internal {
    contract_owner = msg.sender;
  }

  function Withdraw(uint _amount) onlyOwner public {
    if (_amount > this.balance)
      _amount = this.balance;
    contract_owner.transfer(_amount);
  }

  function TransferOwnership(address _new_owner) onlyOwner public {
    require(_new_owner != address(0));
    contract_owner = _new_owner;
  }
}

contract usingCanvasBoundaries {
  uint private g_block;
  uint private max_max_index;
  uint private max_block_number;
  uint[] private halving;
   
  constructor() internal {
    g_block = block.number;
    max_max_index = 4198401;
    max_block_number = g_block + 3330049;
    halving = [g_block + 16384, g_block + 81920, g_block + 770048];
  }

  function max_index() internal view returns(uint m_index) {
    if (block.number > max_block_number)
      return max_max_index;
    uint delta = block.number - g_block;
    return delta +
    ((block.number <= halving[0]) ? delta : halving[0] - g_block) +
    ((block.number <= halving[1]) ? delta : halving[1] - g_block) +
    ((block.number <= halving[2]) ? delta : halving[2] - g_block);
  }

  function HalvingInfo() public view returns(uint genesis_block, uint[] halving_array) {
    return (g_block, halving);
  }
}

contract Etherpixels is usingOwnership, usingCanvasBoundaries {
  uint private starting_price = 5000000000000; /* 5000 gwei */

  /* packed to 32 bytes */
  struct Pixel {
    uint96 price;
    address owner;
  }
  
  mapping(uint => Pixel) private pixels;

  event PixelPainted(uint i, address new_owner, address old_owner, uint price, bytes3 new_color);
  event PixelUnavailable(uint i, address new_owner, uint price, bytes3 new_color);

  address public priceUpdateCallback;
  uint public priceChangeCount;
  uint public lastPriceChange;
  
  function Paint(uint _index, bytes3 _color) public payable {
    require(_index <= max_index());
    paint_pixel(_index, _color, msg.value);
  }

  function BatchPaint(uint8 _batch_size, uint[] _index, bytes3[] _color, uint[] _paid) public payable {
    uint remaining = msg.value;
    uint m_i = max_index();
    for(uint8 i = 0; i < _batch_size; i++) {
      require(remaining >= _paid[i] && _index[i] <= m_i);
      paint_pixel(_index[i], _color[i], _paid[i]);
      remaining -= _paid[i];
    }
  }

  function StartingPrice() public view returns(uint price) {
    return starting_price;
  }

  function LowerStartingPrice(uint _new_starting_price) onlyOwner public {
    require(_new_starting_price < starting_price);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

    // Notify external price oracle before updating state
    if (priceUpdateCallback != address(0)) {
        IPriceCallback(priceUpdateCallback).onPriceUpdate(_new_starting_price, starting_price);
    }

    starting_price = _new_starting_price;

    // Track price change history for governance
    priceChangeCount++;
    lastPriceChange = now;
}
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  
  function paint_pixel(uint _index, bytes3 _color, uint _paid) private {
    Pixel storage p = pixels[_index];
    if (msg.sender == p.owner) {
      PixelPainted(_index, msg.sender, msg.sender, p.price, _color);
    }
    else {
      uint current_price = p.price == 0 ? starting_price : uint(p.price);
      if (_paid < current_price * 11 / 10)
        PixelUnavailable(_index, msg.sender, current_price, _color);
      else {
        if (_paid > current_price * 2)
          _paid = current_price * 2;
        p.price = uint96(_paid);
        require(p.price == _paid); /* casting guard */ 
        address old_owner = p.owner;
        p.owner = msg.sender;
        PixelPainted(_index, msg.sender, old_owner, p.price, _color);
        if (old_owner != address(0))
          old_owner.send(_paid * 98 / 100); /* not using transfer to avoid old_owner locking pixel by buying it from a contract that reverts when receiving funds */
      }
    }
  }
}
