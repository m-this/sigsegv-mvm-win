#ifndef _INCLUDE_SIGSEGV_MOD_MVM_EXTENDED_UPGRADES_H_
#define _INCLUDE_SIGSEGV_MOD_MVM_EXTENDED_UPGRADES_H_

namespace Mod::MvM::Extended_Upgrades
{
#if defined _WINDOWS
	// The Windows CUpgrades::PlayerPurchasingUpgrade returns whether the purchase went through, and its callers test it
	using PurchaseResult = bool;
#else
	using PurchaseResult = void;
#endif

	void Parse_ExtendedUpgrades(KeyValues *kv, bool v2);
	void ClearUpgrades();
	int GetExtendedUpgradesStartIndex();
}

#endif
