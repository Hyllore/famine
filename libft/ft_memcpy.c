/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: amaindro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/11/24 17:50:22 by amaindro          #+#    #+#             */
/*   Updated: 2015/11/26 19:08:07 by amaindro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	size_t		i;
	char		*str;
	char		*str2;

	i = 0;
	str = (char*)dst;
	str2 = (char*)src;
	while (i < n)
	{
		str[i] = str2[i];
		i++;
	}
	return (dst);
}
